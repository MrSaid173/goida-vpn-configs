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
WORKERS = 40 # Можно чуть поднять

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
zone = zoneinfo.ZoneInfo("Europe/Moscow")
now_date = datetime.now(zone)
offset = now_date.strftime("%H:%M | %d.%m.%Y")

def test_config_real(vless_link, local_port):
    config_file = f"config_{local_port}.json"
    proc = None
    try:
        # ПАРСИНГ
        pattern = r"vless://([^@]+)@([^:]+):(\d+)\?([^#]+)"
        match = re.match(pattern, vless_link)
        if not match: return False, "ParseError", 0
        
        uuid, address, port, params_str = match.groups()
        params = dict(re.findall(r'([^&=]+)=([^&]*)', params_str))
        
        # ГЕНЕРАЦИЯ КОНФИГА
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
        
        # ЗАПУСК XRAY
        if not os.path.exists(XRAY_BIN): return False, "NoXrayBinary", 0
        
        proc = subprocess.Popen([XRAY_BIN, "-c", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.8) # Чуть увеличим для стабильности

        # ТЕСТ ЧЕРЕЗ CLOUDFLARE
        proxies = {"http": f"socks5h://127.0.0.1:{local_port}", "https": f"socks5h://127.0.0.1:{local_port}"}
        r = requests.get("https://speed.cloudflare.com/meta", proxies=proxies, timeout=5).json()
        
        country = r.get("country", "??")
        client_ip = r.get("clientIp", "")
        is_ipv6 = ":" in client_ip
        
        if is_ipv6: return False, "IPv6_Blocked", 0
        return True, country, 200 # Условно 200ms

    except Exception as e:
        return False, f"Err:{type(e).__name__}", 0
    finally:
        if proc:
            proc.terminate()
            proc.wait()
        if os.path.exists(config_file): os.remove(config_file)

def main():
    print(f"--- ЗАПУСК СКРИПТА {offset} ---")
    g = Github(auth=Auth.Token(GITHUB_TOKEN)) if GITHUB_TOKEN else None
    repo = g.get_repo(REPO_NAME) if g else None

    # ПРОВЕРКА XRAY
    if not os.path.exists(XRAY_BIN):
        print("⚠️ Xray не найден в репозитории!")
        # Здесь должна быть логика скачивания, которую мы обсуждали ранее
    
    # СБОР ССЫЛОК
    print("📥 Получение списка источников...")
    try:
        resp = requests.get(REMOTE_SOURCE_URL, timeout=15)
        source_urls = re.findall(r'["\'](https?://[^"\']+)["\']', resp.text)
        print(f"🔎 Найдено {len(source_urls)} источников под-ссылок")
        
        raw_configs = []
        for u in source_urls:
            try:
                r = requests.get(u, timeout=10)
                cfgs = re.findall(r'vless://[^\s]+', r.text)
                raw_configs.extend(cfgs)
            except: continue
        
        raw_configs = list(set(raw_configs))
        print(f"📦 Всего уникальных конфигов для проверки: {len(raw_configs)}")
    except Exception as e:
        print(f"❌ Ошибка сбора ссылок: {e}")
        return

    # ТЕСТИРОВАНИЕ
    vlm_list, vlm2_list = [], []
    seen_ips, subnet_counts, ru_count = set(), {}, 0
    total_tested = 0

    print(f"🚀 Начинаем тест в {WORKERS} потоков...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = {executor.submit(test_config_real, cfg, 20000 + i): cfg for i, cfg in enumerate(raw_configs[:2000])} # Берем первые 2000 для теста
        
        for f in concurrent.futures.as_completed(futures):
            total_tested += 1
            cfg = futures[f]
            success, result, _ = f.result()

            if not success:
                # Печатаем ошибки только иногда, чтобы не забить лог
                if total_tested % 100 == 0: print(f" [LOG] Проверено {total_tested}... Последний отказ: {result}")
                continue

            # Если успех, проверяем IP и лимиты
            host_m = re.search(r'@([^:/?#\s]+)', cfg)
            ip_host = host_m.group(1)
            try:
                ip_addr = socket.gethostbyname(ip_host)
                subnet = ".".join(ip_addr.split(".")[:3])
            except: continue

            if ip_addr in seen_ips or subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET:
                continue

            if result == "RU":
                if ru_count >= MAX_RU_CONFIGS: continue
                ru_count += 1

            # Добавляем!
            vlm2_list.append(cfg)
            if "xhttp" not in cfg.lower(): vlm_list.append(cfg)
            
            seen_ips.add(ip_addr)
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
            print(f" ✅ ДОБАВЛЕН: {ip_addr} | Страна: {result} | Всего: {len(vlm2_list)}")

            if len(vlm2_list) >= MAX_CONFIGS: break

    print(f"🏁 Тест окончен. Проверено: {total_tested}. Найдено рабочих: {len(vlm2_list)}")

    # СОХРАНЕНИЕ (Оставь как было)
    # save_file(...)

if __name__ == "__main__":
    main()
