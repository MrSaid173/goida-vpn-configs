import os, re, requests, urllib3, concurrent.futures, ipaddress, base64, json, time, socket
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

# Определяем путь к базе данных в той же папке, где лежит скрипт
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MMDB_PATH = os.path.join(BASE_DIR, "GeoLite2-Country.mmdb")

EXCLUDE_PROTOCOLS = ("ss://", "trojan://", "vmess://")
EXCLUDE_KEYWORDS = ("openproxy", "type=ws")
MAX_CONFIGS = 150 
MAX_PER_SUBNET = 3 
MAX_PER_SNI = 5
MAX_RU_CONFIGS = 5

# --- ИНИЦИАЛИЗАЦИЯ ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")
g = Github(auth=Auth.Token(GITHUB_TOKEN)) if GITHUB_TOKEN else Github()
REPO = g.get_repo(REPO_NAME)

geo_cache = {}

# --- ФУНКЦИИ ---

def update_mmdb():
    if os.path.exists(MMDB_PATH):
        file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(MMDB_PATH))
        if file_age < timedelta(days=3):
            print(f"✅ База GeoIP актуальна: {MMDB_PATH}")
            return
    print("📥 Обновление базы данных GeoLite...")
    try:
        r = requests.get(MMDB_URL, timeout=30)
        with open(MMDB_PATH, "wb") as f:
            f.write(r.content)
    except Exception as e:
        print(f"⚠️ Ошибка загрузки базы: {e}")

def is_ru_ip(ip_str):
    if ip_str in geo_cache: return geo_cache[ip_str]
    try:
        with maxminddb.open_database(MMDB_PATH) as reader:
            record = reader.get(ip_str)
            if record and 'country' in record:
                is_ru = record['country'].get('iso_code') == 'RU'
                geo_cache[ip_str] = is_ru
                return is_ru
    except Exception as e:
        pass
    return False

def is_server_alive(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except: return False

def get_config_details(link):
    try:
        if link.startswith("vmess://"): return None, None, None
        
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', link)
        
        if h_m:
            host = h_m.group(1)
            port = int(h_m.group(2))
            sni = (s_m.group(1).lower() if s_m else None)

            if not sni: return None, None, None
            
            try:
                if ipaddress.ip_address(host).version == 6: return None, None, None
            except: pass
                
            return host, port, sni
    except: pass
    return None, None, None

def get_remote_data():
    """Получает данные из внешнего репозитория AvenCores"""
    try:
        resp = session.get(REMOTE_SOURCE_URL, timeout=15)
        code = resp.text
        all_lists = re.findall(r'(\w+)\s*=\s*\[(.*?)\]', code, re.DOTALL | re.IGNORECASE)
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
        resp = session.get(url, timeout=15, verify=False)
        text = re.sub(r'(vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', resp.text)
        return [l.strip() for l in text.splitlines() if "://" in l]
    except: return []

# --- ГЛАВНАЯ ЛОГИКА ---

def main():
    update_mmdb()
    
    # Теперь вызываем функцию напрямую без лишних импортов
    extra_urls, std_urls, sni_domains = get_remote_data()
    
    vlm_list, vlm2_list = [], []
    seen_hosts = set()
    sni_counts, subnet_counts = {}, {}
    ru_count = 0

    def process_pool(urls, use_sni_filter=True):
        nonlocal ru_count
        with concurrent.futures.ThreadPoolExecutor(max_workers=35) as executor:
            future_to_url = {executor.submit(fetch_raw_configs, u): u for u in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                configs = future.result()
                for config in configs:
                    if len(vlm_list) >= MAX_CONFIGS and len(vlm2_list) >= MAX_CONFIGS: return

                    low_config = config.lower()
                    if low_config.startswith(EXCLUDE_PROTOCOLS) or any(k in low_config for k in EXCLUDE_KEYWORDS):
                        continue
                    
                    host, port, sni = get_config_details(config)
                    if not host or host in seen_hosts: continue
                    
                    if use_sni_filter and sni_domains:
                        if not any(d in sni for d in sni_domains): continue

                    if sni_counts.get(sni, 0) >= MAX_PER_SNI: continue
                    
                    try: 
                        ip_addr = socket.gethostbyname(host)
                        if ipaddress.ip_address(ip_addr).version == 6: continue
                        subnet = ".".join(ip_addr.split(".")[:3])
                    except: continue

                    if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue

                    if not is_server_alive(host, port): continue
                    
                    if is_ru_ip(ip_addr):
                        if ru_count >= MAX_RU_CONFIGS: continue
                        ru_count += 1

                    added = False
                    is_xhttp = "xhttp" in low_config
                    if len(vlm2_list) < MAX_CONFIGS:
                        vlm2_list.append(config)
                        added = True
                    if not is_xhttp and len(vlm_list) < MAX_CONFIGS:
                        vlm_list.append(config)
                        added = True

                    if added:
                        seen_hosts.add(host)
                        sni_counts[sni] = sni_counts.get(sni, 0) + 1
                        subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                        print(f"✅ OK: {host}")

    process_pool(extra_urls, True)
    if len(vlm_list) < MAX_CONFIGS or len(vlm2_list) < MAX_CONFIGS:
        process_pool(std_urls, True)
    if len(vlm_list) < MAX_CONFIGS or len(vlm2_list) < MAX_CONFIGS:
        process_pool(extra_urls + std_urls, False)

    def save(filename, lst):
        if not lst: return
        data = "\n".join(lst)
        path = f"githubmirror/{filename}"
        msg = f"🚀 {filename} | T: {len(lst)} | RU: {ru_count} | {offset}"
        try:
            curr = REPO.get_contents(path)
            REPO.update_file(path, msg, data, curr.sha)
        except: REPO.create_file(path, msg, data)
        print(f"🏁 {filename} сохранен.")

    save(FILENAME_VLM, vlm_list)
    save(FILENAME_VLM2, vlm2_list)

if __name__ == "__main__":
    main()
    
