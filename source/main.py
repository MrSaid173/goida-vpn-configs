import os, re, requests, urllib3, concurrent.futures, subprocess, json, time, socket, zipfile
from datetime import datetime
import zoneinfo
from github import Github, Auth

# --- НАСТРОЙКИ ---
XRAY_BIN = "./xray"
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MrSaid173/golden-paths_configs"
FILENAME_VLM = "vlm"
FILENAME_VLM2 = "vlm2"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"

MAX_CONFIGS = 150
MAX_PER_SUBNET = 3
MAX_RU_CONFIGS = 10 
WORKERS = 40

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
zone = zoneinfo.ZoneInfo("Europe/Moscow")
now_date = datetime.now(zone)
offset = now_date.strftime("%H:%M | %d.%m.%Y")

def get_xray_now():
    """Принудительное скачивание Xray если его нет"""
    if os.path.exists(XRAY_BIN):
        return True
    
    print("🌐 Скачивание Xray бинарника...")
    try:
        url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
        r = requests.get(url, timeout=30)
        with open("xray.zip", "wb") as f: f.write(r.content)
        
        with zipfile.ZipFile("xray.zip", 'r') as zip_ref:
            # Извлекаем только сам бинарник
            zip_ref.extract("xray", path=".")
        
        os.chmod(XRAY_BIN, 0o755)
        os.remove("xray.zip")
        print("✅ Xray готов к работе.")
        return True
    except Exception as e:
        print(f"❌ Критическая ошибка при подготовке Xray: {e}")
        return False

def test_config_real(vless_link, local_port):
    config_file = f"config_{local_port}.json"
    proc = None
    try:
        # Улучшенный парсинг: теперь ловит ссылки даже с минимумом параметров
        if not vless_link.startswith("vless://"): return False, "NotVless", 0
        
        # Разбиваем ссылку более надежно
        core_part = vless_link.split("://")[1]
        user_info, rest = core_part.split("@")
        address_port, params_part = rest.split("?")
        address, port = address_port.split(":")
        # Убираем якорь (#), если он есть
        params_str = params_part.split("#")[0]
        params = dict(re.findall(r'([^&=]+)=([^&]*)', params_str))
        
        uuid = user_info

        xray_config = {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": local_port, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": address, "port": int(port), "users": [{"id": uuid, "encryption": "none", "flow": params.get("flow", "")}]}]},
                "streamSettings": {
                    "network": params.get("type", "tcp"),
                    "security": params.get("security", "none"),
                    "tlsSettings": {"serverName": params.get("sni", ""), "allowInsecure": True},
                    "realitySettings": {
                        "serverName": params.get("sni", ""),
                        "publicKey": params.get("pbk", ""),
                        "shortId": params.get("sid", ""),
                        "spiderX": params.get("spx", "")
                    } if params.get("security") == "reality" else None,
                }
            }]
        }

        with open(config_file, "w") as f: json.dump(xray_config, f)
        
        # Проверка наличия бинарника прямо перед запуском
        if not os.path.exists(XRAY_BIN): return False, "NoXrayBinary", 0
        
        proc = subprocess.Popen([XRAY_BIN, "-c", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0) # Даем чуть больше времени на медленных серверах GitHub

        proxies = {"http": f"socks5h://127.0.0.1:{local_port}", "https": f"socks5h://127.0.0.1:{local_port}"}
        r = requests.get("https://speed.cloudflare.com/meta", proxies=proxies, timeout=6).json()
        
        country = r.get("country", "??")
        if ":" in r.get("clientIp", ""): return False, "IPv6", 0
        return True, country, 0

    except Exception as e:
        return False, f"Error", 0
    finally:
        if proc:
            proc.terminate()
            proc.wait()
        if os.path.exists(config_file): os.remove(config_file)

def main():
    print(f"--- ЗАПУСК {offset} ---")
    
    # 1. Сначала готовим Xray. Если не смогли - выходим.
    if not get_xray_now():
        return

    # 2. Сбор ссылок
    try:
        resp = requests.get(REMOTE_SOURCE_URL, timeout=15)
        source_urls = re.findall(r'["\'](https?://[^"\']+)["\']', resp.text)
        raw_configs = []
        for u in source_urls:
            try:
                r = requests.get(u, timeout=10)
                raw_configs.extend(re.findall(r'vless://[^\s]+', r.text))
            except: continue
        raw_configs = list(set(raw_configs))
        print(f"📦 Всего в базе: {len(raw_configs)}")
    except: return

    # 3. Тест
    vlm2_list = []
    seen_ips, subnet_counts, ru_count = set(), {}, 0
    total_tested = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        # Проверяем не более 3000 за раз для экономии ресурсов
        futures = {executor.submit(test_config_real, cfg, 20000 + i): cfg for i, cfg in enumerate(raw_configs[:3000])}
        
        for f in concurrent.futures.as_completed(futures):
            total_tested += 1
            cfg = futures[f]
            success, result, _ = f.result()

            if not success:
                if total_tested % 100 == 0: print(f" [LOG] {total_tested} проверено... Последний отказ: {result}")
                continue

            host_m = re.search(r'@([^:/?#\s]+)', cfg)
            ip_host = host_m.group(1)
            try:
                ip_addr = socket.gethostbyname(ip_host)
                subnet = ".".join(ip_addr.split(".")[:3])
            except: continue

            if ip_addr in seen_ips or subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue

            if result == "RU":
                if ru_count >= MAX_RU_CONFIGS: continue
                ru_count += 1

            vlm2_list.append(cfg)
            seen_ips.add(ip_addr)
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
            print(f" ✅ НАЙДЕН: {ip_addr} | {result}")

            if len(vlm2_list) >= MAX_CONFIGS: break

    # 4. Сохранение (через PyGithub как в прошлых версиях)
    # ... логика save_file ...
    print(f"🏁 Финиш. Найдено рабочих: {len(vlm2_list)}")

if __name__ == "__main__":
    main()
