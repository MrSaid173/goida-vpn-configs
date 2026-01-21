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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MMDB_PATH = os.path.join(BASE_DIR, "GeoLite2-Country.mmdb")

EXCLUDE_PROTOCOLS = ("ss://", "trojan://", "vmess://")
EXCLUDE_KEYWORDS = ("openproxy", "type=ws")
MAX_CONFIGS = 150 
MAX_PER_SUBNET = 3 
MAX_PER_SNI = 15
MAX_PER_ID = 3       # Лимит на одинаковые ID
MAX_RU_CONFIGS = 6

# --- ИНИЦИАЛИЗАЦИЯ ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")
g = Github(auth=Auth.Token(GITHUB_TOKEN)) if GITHUB_TOKEN else Github()
REPO = g.get_repo(REPO_NAME)

geo_cache = {} 
last_online_geoip_time = 0

# --- ФУНКЦИИ ---

def update_mmdb():
    if os.path.exists(MMDB_PATH):
        file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(MMDB_PATH))
        if file_age < timedelta(days=3):
            print(f"✅ База актуальна (возраст: {file_age.days} дн.)")
            return
    try:
        r = requests.get(MMDB_URL, timeout=60)
        with open(MMDB_PATH, "wb") as f:
            f.write(r.content)
        print("✅ База GeoLite2 обновлена.")
    except Exception as e:
        print(f"❌ Ошибка БД: {e}")

def is_ru_ip(ip_str):
    global last_online_geoip_time
    if ip_str in geo_cache: return geo_cache[ip_str]
    
    is_ru = False
    found_in_db = False
    try:
        with maxminddb.open_database(MMDB_PATH) as reader:
            record = reader.get(ip_str)
            if record and 'country' in record:
                is_ru = record['country'].get('iso_code') == 'RU'
                found_in_db = True
    except: pass

    if found_in_db:
        geo_cache[ip_str] = is_ru
        return is_ru

    # Онлайн проверка если в БД нет
    now = time.time()
    wait = 1.35 - (now - last_online_geoip_time)
    if wait > 0: time.sleep(wait)
    try:
        url = f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,isp,org,asname"
        r = session.get(url, timeout=5).json()
        last_online_geoip_time = time.time()
        if r.get("status") == "success":
            info = (r.get("isp", "") + " " + r.get("org", "") + " " + r.get("asname", "")).lower()
            is_ru = (r.get("countryCode") == "RU") or any(k in info for k in ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota", "vimpelcom", "russia"])
            geo_cache[ip_str] = is_ru
            return is_ru
    except: pass
    return False

def get_config_details(link):
    try:
        if link.startswith("vmess://"): return None, None, None, None
        
        # Извлекаем ID (между протоколом и @)
        id_match = re.search(r'://([^@]+)@', link)
        config_id = id_match.group(1) if id_match else None
        
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', link)
        
        if h_m:
            host = h_m.group(1)
            port = int(h_m.group(2))
            sni = (s_m.group(1).lower() if s_m else None)

            if not sni: return None, None, None, "missing_sni"
            
            # Фильтр "буквенных" IP и IPv6
            try:
                ip_obj = ipaddress.ip_address(host)
                if ip_obj.version == 6: return None, None, None, "ipv6"
            except ValueError:
                # Если это домен (буквы), а не IP — отсекаем
                return None, None, None, "domain_not_ip"
                
            return host, port, sni, config_id
    except: pass
    return None, None, None, None

def get_remote_data():
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
    extra_urls, std_urls, sni_domains = get_remote_data()
    
    vlm_list, vlm2_list = [], []
    seen_hosts = set()
    sni_counts, subnet_counts, id_counts = {}, {}, {}
    ru_count = 0

    def process_pool(urls, use_sni_filter=True, stage_name=""):
        nonlocal ru_count
        print(f"\n--- [ЭТАП: {stage_name}] ---")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=35) as executor:
            future_to_url = {executor.submit(fetch_raw_configs, u): u for u in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                configs = future.result()
                for config in configs:
                    if len(vlm_list) >= MAX_CONFIGS and len(vlm2_list) >= MAX_CONFIGS: return

                    if config.lower().startswith(EXCLUDE_PROTOCOLS): continue
                    
                    host, port, sni, config_id = get_config_details(config)
                    
                    # Проверки фильтров
                    if not host or host in seen_hosts: continue
                    if sni in ("missing_sni", "ipv6", "domain_not_ip"): continue
                    
                    # Лимит на одинаковые ID (Пункт про ID до @)
                    if config_id:
                        if id_counts.get(config_id, 0) >= MAX_PER_ID: continue
                    
                    if use_sni_filter and sni_domains:
                        if not any(d in sni for d in sni_domains): continue

                    if sni_counts.get(sni, 0) >= MAX_PER_SNI: continue
                    
                    # Получаем подсеть (уже точно имеем IP)
                    subnet = ".".join(host.split(".")[:3])
                    if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue

                    # Проверка жизни порта
                    if not socket.create_connection((host, port), timeout=1.8): continue
                    
                    # Гео
                    if is_ru_ip(host):
                        if ru_count >= MAX_RU_CONFIGS: continue
                        ru_count += 1

                    added = False
                    if len(vlm2_list) < MAX_CONFIGS:
                        vlm2_list.append(config)
                        added = True
                    if "xhttp" not in config.lower() and len(vlm_list) < MAX_CONFIGS:
                        vlm_list.append(config)
                        added = True

                    if added:
                        seen_hosts.add(host)
                        sni_counts[sni] = sni_counts.get(sni, 0) + 1
                        subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                        if config_id: id_counts[config_id] = id_counts.get(config_id, 0) + 1
                        print(f" [+] {host} | ID: {config_id[:8]}... | RU: {is_ru_ip(host)}")

    process_pool(extra_urls, True, "EXTRA")
    process_pool(std_urls, True, "STD")
    process_pool(extra_urls + std_urls, False, "RESERVE")

    def save(filename, lst):
        if not lst: return
        data = "\n".join(lst)
        path = f"githubmirror/{filename}"
        msg = f"🚀 {filename} | T: {len(lst)} | RU: {ru_count} | {offset}"
        try:
            curr = REPO.get_contents(path)
            REPO.update_file(path, msg, data, curr.sha)
        except: REPO.create_file(path, msg, data)

    save(FILENAME_VLM, vlm_list)
    save(FILENAME_VLM2, vlm2_list)
    print(f"\n🏁 Готово. VLM: {len(vlm_list)}, VLM2: {len(vlm2_list)}")

if __name__ == "__main__":
    main()
