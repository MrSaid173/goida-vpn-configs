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
WORKERS = 20 # Уменьшили для стабильности в GitHub Actions

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
zone = zoneinfo.ZoneInfo("Europe/Moscow")
now_date = datetime.now(zone)
offset = now_date.strftime("%H:%M | %d.%m.%Y")

def get_xray_now():
    """Синхронная подготовка бинарника"""
    if os.path.exists(XRAY_BIN):
        return True
    print("🌐 Скачивание Xray бинарника...")
    try:
        url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
        r = requests.get(url, timeout=30)
        with open("xray.zip", "wb") as f: f.write(r.content)
        with zipfile.ZipFile("xray.zip", 'r') as zip_ref:
            zip_ref.extract("xray", path=".")
        os.chmod(XRAY_BIN, 0o755)
        os.remove("xray.zip")
        print("✅ Xray готов.")
        return True
    except Exception as e:
        print(f"❌ Ошибка подготовки Xray: {e}")
        return False

def test_config_real(vless_link, local_port):
    config_file = f"config_{local_port}.json"
    proc = None
    try:
        # 1. Парсинг ссылки через Regex + Очистка
        m = re.match(r"vless://([^@]+)@([^:]+):(\d+)\?(.*)", vless_link)
        if not m: return False, "ParseError"
        
        uuid, address, port, raw_params = m.groups()
        params_str = raw_params.split("#")[0]
        params = dict(re.findall(r'([^&=]+)=([^&]*)', params_str))

        # 2. Формирование чистого конфига
        stream_settings = {
            "network": params.get("type", "tcp"),
            "security": params.get("security", "none")
        }
        
        if params.get("security") == "tls":
            stream_settings["tlsSettings"] = {"serverName": params.get("sni", ""), "allowInsecure": True}
        elif params.get("security") == "reality":
            stream_settings["realitySettings"] = {
                "serverName": params.get("sni", ""),
                "publicKey": params.get("pbk", ""),
                "shortId": params.get("sid", ""),
                "spiderX": params.get("spx", "")
            }

        if params.get("type") == "ws":
            stream_settings["wsSettings"] = {"path": params.get("path", "/")}
        elif params.get("type") == "grpc":
            stream_settings["grpcSettings"] = {"serviceName": params.get("serviceName", "")}

        xray_config = {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": local_port, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": address, "port": int(port), "users": [{"id": uuid, "encryption": "none", "flow": params.get("flow", "")}]}]},
                "streamSettings": stream_settings
            }]
        }

        with open(config_file, "w") as f: json.dump(xray_config, f)
        
        # 3. Запуск и проверка живой ли процесс
        proc = subprocess.Popen([XRAY_BIN, "-c", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.2)
        
        if proc.poll() is not None: return False, "XrayCrash"

        # 4. Попытка запроса
        proxies = {"http": f"socks5h://127.0.0.1:{local_port}", "https": f"socks5h://127.0.0.1:{local_port}"}
        try:
            r = requests.get("https://speed.cloudflare.com/meta", proxies=proxies, timeout=7)
            data = r.json()
            if ":" in data.get("clientIp", ""): return False, "IPv6"
            return True, data.get("country", "??")
        except requests.exceptions.ProxyError: return False, "ProxyRefused"
        except requests.exceptions.Timeout: return False, "Timeout"
        except Exception as e: return False, f"ReqErr:{type(e).__name__}"

    except Exception as e: return False, f"LogicErr:{str(e)[:10]}"
    finally:
        if proc:
            try: proc.terminate()
            except: pass
        if os.path.exists(config_file):
            try: os.remove(config_file)
            except: pass

def main():
    print(f"--- СТАРТ: {offset} ---")
    if not get_xray_now(): return
    
    auth = Auth.Token(GITHUB_TOKEN)
    g = Github(auth=auth)
    repo = g.get_repo(REPO_NAME)

    # Получение ссылок
    try:
        resp = requests.get(REMOTE_SOURCE_URL, timeout=15)
        sources = re.findall(r'["\'](https?://[^"\']+)["\']', resp.text)
        raw_configs = []
        for s in sources:
            try:
                r = requests.get(s, timeout=10)
                raw_configs.extend(re.findall(r'vless://[^\s]+', r.text))
            except: continue
        raw_configs = list(set(raw_configs))
        print(f"📦 Собрано ссылок: {len(raw_configs)}")
    except: return

    vlm2_list, vlm_list = [], []
    seen_ips, subnet_counts, ru_count = set(), {}, 0
    total_checked = 0

    print(f"🚀 Тестируем (воркеры: {WORKERS})...")
    
    # Ограничиваем первую пачку для теста, чтобы увидеть результат быстрее
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = {executor.submit(test_config_real, cfg, 20000 + i): cfg for i, cfg in enumerate(raw_configs[:2500])}
        
        for f in concurrent.futures.as_completed(futures):
            total_checked += 1
            cfg = futures[f]
            success, result = f.result()

            if not success:
                if total_checked % 100 == 0:
                    print(f" [LOG] Проверено {total_checked}. Статус: {result}")
                continue

            # Извлечение IP для фильтров
            host_m = re.search(r'@([^:/?#\s]+)', cfg)
            if not host_m: continue
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
            if "xhttp" not in cfg.lower(): vlm_list.append(cfg)
            
            seen_ips.add(ip_addr)
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
            print(f" ✅ НАЙДЕН: {ip_addr} | Страна: {result}")

            if len(vlm2_list) >= MAX_CONFIGS: break

    # Сохранение
    def save(name, data):
        path = f"githubmirror/{name}"
        msg = f"🚀 {name} | T: {len(data)} | RU: {ru_count} | {offset}"
        try:
            sha = repo.get_contents(path).sha
            repo.update_file(path, msg, "\n".join(data), sha)
        except: repo.create_file(path, msg, "\n".join(data))

    if vlm2_list:
        save(FILENAME_VLM, vlm_list)
        save(FILENAME_VLM2, vlm2_list)
        print(f"🏁 Успех! Сохранено {len(vlm2_list)} конфигов.")
    else:
        print("❌ Не найдено ни одного рабочего конфига.")

if __name__ == "__main__":
    main()
