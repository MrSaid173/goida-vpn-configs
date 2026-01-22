import os, re, requests, urllib3, concurrent.futures, ipaddress, json, time, socket, subprocess, zipfile
from datetime import datetime, timedelta
import zoneinfo
from github import Github, Auth
import maxminddb

# --- НАСТРОЙКИ ---
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MrSaid173/golden-paths_configs"
FILENAME_VLM = "vlm"
FILENAME_VLM2 = "vlm2"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
MMDB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
XRAY_BIN = "./xray"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MMDB_PATH = os.path.join(BASE_DIR, "GeoLite2-Country.mmdb")

EXCLUDE_PROTOCOLS = ("ss://", "trojan://", "vmess://")
MAX_CONFIGS = 150 
MAX_PER_SUBNET = 3 
MAX_PER_SNI = 15
MAX_PER_ID = 3
MAX_RU_CONFIGS = 6

# Словарь для поиска стран в названии
COUNTRY_MAP = {
    "RU": ["russia", "россия", "rus"],
    "US": ["usa", "united states", "сша"],
    "DE": ["germany", "германия", "deutschland"],
    "NL": ["netherlands", "нидерланды", "holland"],
    "FI": ["finland", "финляндия"],
    "TR": ["turkey", "турция"],
    "KZ": ["kazakhstan", "казахстан",],
    "GB": ["united kingdom", "британ"],
    "FR": ["france", "франция"]
}

# --- ИНИЦИАЛИЗАЦИЯ ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
start_time = datetime.now(zone)
offset = start_time.strftime("%H:%M | %d.%m.%Y")
g = Github(auth=Auth.Token(GITHUB_TOKEN)) if GITHUB_TOKEN else Github()
REPO = g.get_repo(REPO_NAME)

geo_cache = {} 
last_online_geoip_time = 0

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---

def setup_xray():
    if os.path.exists(XRAY_BIN): return True
    try:
        r = requests.get("https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip", timeout=30)
        with open("xray.zip", "wb") as f: f.write(r.content)
        with zipfile.ZipFile("xray.zip", 'r') as z: z.extract("xray", path=".")
        os.chmod(XRAY_BIN, 0o755)
        return True
    except: return False

def get_country_from_name(link):
    name = link.split("#")[-1].lower() if "#" in link else ""
    for iso, keywords in COUNTRY_MAP.items():
        if any(k in name for k in keywords): return iso
    return None

def test_xray_connectivity(vless_link, local_port):
    """Проверка через Xray: cp.cloudflare.com и gstatic.com (3s timeout)"""
    config_file = f"temp_{local_port}.json"
    proc = None
    try:
        # Упрощенный парсинг для теста
        main_part = vless_link.split("://")[1].split("#")[0]
        user_info, rest = main_part.split("@")
        addr_port = rest.split("?")[0]
        address, port = addr_port.split(":")
        
        x_cfg = {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": local_port, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": address, "port": int(port), "users": [{"id": user_info}]}]}}]
        }
        with open(config_file, "w") as f: json.dump(x_cfg, f)
        
        proc = subprocess.Popen([XRAY_BIN, "-c", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        
        proxies = {'http': f'socks5h://127.0.0.1:{local_port}', 'https': f'socks5h://127.0.0.1:{local_port}'}
        # Пункт 2: Проверка через оба URL
        r1 = session.get("http://cp.cloudflare.com", proxies=proxies, timeout=3)
        r2 = session.get("http://www.gstatic.com/generate_204", proxies=proxies, timeout=3)
        
        return r1.status_code < 400 and r2.status_code == 204
    except: return False
    finally:
        if proc: proc.terminate()
        if os.path.exists(config_file): os.remove(config_file)

def get_ip_info_online(ip_str):
    """Получает страну и проверяет на Cloudflare (Пункт 1)"""
    global last_online_geoip_time
    now = time.time()
    wait = 1.35 - (now - last_online_geoip_time)
    if wait > 0: time.sleep(wait)
    try:
        url = f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,org,isp,asname"
        r = session.get(url, timeout=5).json()
        last_online_geoip_time = time.time()
        if r.get("status") == "success":
            org_info = (r.get("org", "") + " " + r.get("isp", "") + " " + r.get("asname", "")).lower()
            # Пункт 1: Фильтр Cloudflare
            if "cloudflare" in org_info: return "CLOUDFLARE", True
            
            is_ru = (r.get("countryCode") == "RU") or any(k in org_info for k in ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota", "vimpelcom"])
            return r.get("countryCode"), is_ru
    except: pass
    return None, False

# --- ОСТАЛЬНЫЕ ФУНКЦИИ (update_mmdb, get_config_details, etc) ---
# ... (Оставляем их как в твоем исходном коде) ...
def update_mmdb():
    if os.path.exists(MMDB_PATH):
        file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(MMDB_PATH))
        if file_age < timedelta(days=3): return
    try:
        r = requests.get(MMDB_URL, timeout=60)
        with open(MMDB_PATH, "wb") as f: f.write(r.content)
    except: pass

def get_config_details(link):
    try:
        if link.startswith("vmess://"): return None, None, None, None
        id_match = re.search(r'://([^@]+)@', link)
        config_id = id_match.group(1) if id_match else None
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', link)
        if h_m:
            host, port = h_m.group(1), int(h_m.group(2))
            sni = (s_m.group(1).lower() if s_m else None)
            if not sni: return None, None, None, None
            return host, port, sni, config_id
    except: pass
    return None, None, None, None

def get_remote_data():
    try:
        resp = session.get(REMOTE_SOURCE_URL, timeout=15)
        all_lists = re.findall(r'(\w+)\s*=\s*\[(.*?)\]', resp.text, re.DOTALL | re.IGNORECASE)
        std_src, extra_src, sni_list = [], [], []
        for var, content in all_lists:
            items = re.findall(r'["\']([^"\']+)["\']', content)
            if var.upper() == "URLS": std_src = items
            elif var.upper() == "EXTRA_URLS_FOR_26": extra_src = items
            elif var.upper() == "SNI_DOMAINS": sni_list = items
        return extra_src, std_src, sni_list
    except: return [], [], []

def fetch_raw_configs(url):
    try:
        resp = session.get(url, timeout=10, verify=False)
        text = re.sub(r'(vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', resp.text)
        return [l.strip() for l in text.splitlines() if "://" in l]
    except: return []

# --- ГЛАВНАЯ ЛОГИКА ---

def main():
    setup_xray()
    update_mmdb()
    extra_urls, std_urls, sni_domains = get_remote_data()
    
    vlm_list, vlm2_list = [], []
    seen_hosts = set()
    sni_counts, subnet_counts, id_counts = {}, {}, {}
    ru_count = 0

    with maxminddb.open_database(MMDB_PATH) as mmdb_reader:

        def process_pool(urls, use_sni_filter=True, stage_name=""):
            nonlocal ru_count
            print(f"\n--- [ЭТАП: {stage_name}] ---")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor: # Уменьшено для Xray
                future_to_url = {executor.submit(fetch_raw_configs, u): u for u in urls}
                for future in concurrent.futures.as_completed(future_to_url):
                    configs = future.result()
                    for i, config in enumerate(configs):
                        if len(vlm2_list) >= MAX_CONFIGS: return

                        if config.lower().startswith(EXCLUDE_PROTOCOLS): continue
                        
                        host, port, sni, config_id = get_config_details(config)
                        if not host or host in seen_hosts: continue
                        if use_sni_filter and sni_domains and not any(d in sni for d in sni_domains): continue
                        if sni_counts.get(sni, 0) >= MAX_PER_SNI or id_counts.get(config_id, 0) >= MAX_PER_ID: continue
                        
                        try:
                            ip_addr = socket.gethostbyname(host)
                            subnet = ".".join(ip_addr.split(".")[:3])
                        except: continue

                        if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue

                        # 1. ГЕО и ФИЛЬТР CLOUDFLARE (Пункт 1)
                        real_iso, is_ru = None, False
                        record = mmdb_reader.get(ip_addr)
                        if record and 'country' in record:
                            real_iso = record['country'].get('iso_code')
                            is_ru = (real_iso == 'RU')

                        # Если нет в базе или нужно проверить организацию
                        online_iso, online_ru = get_ip_info_online(ip_addr)
                        if online_iso == "CLOUDFLARE": continue # Исключаем Cloudflare
                        
                        if online_iso: 
                            real_iso = online_iso
                            is_ru = online_ru

                        # 2. СВЕРКА СТРАНЫ В НАЗВАНИИ (Пункт 3)
                        name_iso = get_country_from_name(config)
                        if name_iso and name_iso != real_iso: continue

                        if is_ru and ru_count >= MAX_RU_CONFIGS: continue

                        # 3. РЕАЛЬНЫЙ ТЕСТ ЧЕРЕЗ XRAY (Пункт 2)
                        # Используем порт на основе индекса, чтобы потоки не конфликтовали
                        if not test_xray_connectivity(config, 21000 + (total_tested % 100)): continue

                        # ЕСЛИ ВСЁ ПРОШЛО:
                        if is_ru: ru_count += 1
                        
                        added = False
                        if len(vlm2_list) < MAX_CONFIGS:
                            vlm2_list.append(config)
                            added = True
                        if "xhttp" not in config.lower() and len(vlm_list) < MAX_CONFIGS:
                            vlm_list.append(config)

                        if added:
                            seen_hosts.add(host)
                            sni_counts[sni] = sni_counts.get(sni, 0) + 1
                            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                            if config_id: id_counts[config_id] = id_counts.get(config_id, 0) + 1
                            print(f" [+] {ip_addr} | {real_iso} | RU: {is_ru}")

        total_tested = 0
        process_pool(extra_urls, True, "EXTRA")
        process_pool(std_urls, True, "STD")
        process_pool(extra_urls + std_urls, False, "RESERVE")

    # Сохранение
    def save(filename, lst):
        if not lst: return
        path = f"githubmirror/{filename}"
        msg = f"🚀 {filename} | T: {len(lst)} | RU: {ru_count} | {offset}"
        try:
            sha = REPO.get_contents(path).sha
            REPO.update_file(path, msg, "\n".join(lst), sha)
        except: REPO.create_file(path, msg, "\n".join(lst))

    save(FILENAME_VLM, vlm_list)
    save(FILENAME_VLM2, vlm2_list)
    print(f"\n🏁 Готово. Время: {str(datetime.now(zone)-start_time).split('.')[0]}")

if __name__ == "__main__":
    main()
