import os, re, requests, urllib3, concurrent.futures, ipaddress, base64, json, time, socket, ssl
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
MAX_CONFIGS = 150 
MAX_PER_SUBNET = 3 
MAX_PER_SNI = 15
MAX_PER_ID = 3
MAX_RU_CONFIGS = 6

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

# --- УМНЫЙ ПИНГ (TLS HANDSHAKE) ---
def smart_ping(host, port, sni):
    """Проверяет не только порт, но и готовность сервера к TLS соединению"""
    try:
        # Создаем контекст без проверки сертификата (для скорости)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Устанавливаем соединение
        with socket.create_connection((host, port), timeout=1.2) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                # Если мы дошли до сюда, значит TLS-рукопожатие прошло успешно
                return True
    except:
        return False

# --- ОСТАЛЬНЫЕ ФУНКЦИИ ---
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
        link = re.sub(r'[^\x20-\x7E]', '', link).strip() # Очистка от мусора
        if link.startswith("vmess://"): return None, None, None, None
        id_match = re.search(r'://([^@]+)@', link)
        config_id = id_match.group(1) if id_match else None
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', link)
        if h_m:
            host, port = h_m.group(1), int(h_m.group(2))
            sni = s_m.group(1).lower() if s_m else ""
            return host, port, sni, config_id
    except: pass
    return None, None, None, None

def fetch_raw_configs(url):
    try:
        resp = session.get(url, timeout=12, verify=False).text
        # Поддержка Base64 для LalatinaHub и др.
        if "://" not in resp[:50] and len(resp) > 64:
            try: resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
            except: pass
        text = re.sub(r'(vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', resp)
        return [l.strip() for l in text.splitlines() if "vless://" in l]
    except: return []

# --- ГЛАВНАЯ ЛОГИКА ---
def main():
    update_mmdb()
    # Собираем данные об источниках (URLS, EXTRA_URLS_FOR_26, SNI_DOMAINS)
    try:
        src = session.get(REMOTE_SOURCE_URL).text
        def get_list(name):
            m = re.search(rf'{name}\s*=\s*\[(.*?)\]', src, re.S)
            return re.findall(r'["\'](https?://[^"\']+)["\']', m.group(1)) if m else []
        
        extra_urls = get_list("EXTRA_URLS_FOR_26")
        std_urls = get_list("URLS")
        sni_match = re.search(r'SNI_DOMAINS\s*=\s*\[(.*?)\]', src, re.S)
        sni_domains = [s.strip(" \"'") for s in sni_match.group(1).split(",")] if sni_match else []
    except: return

    vlm_list, vlm2_list = [], []
    seen_hosts, sni_counts, subnet_counts, id_counts, ru_count = set(), {}, {}, {}, 0

    

    with maxminddb.open_database(MMDB_PATH) as mmdb_reader:
        def process_pool(urls, use_sni_filter, stage_name):
            nonlocal ru_count
            print(f"--- [ЭТАП: {stage_name}] ---")
            with concurrent.futures.ThreadPoolExecutor(max_workers=35) as executor:
                future_to_url = {executor.submit(fetch_raw_configs, u): u for u in urls}
                for future in concurrent.futures.as_completed(future_to_url):
                    for config in future.result():
                        if len(vlm2_list) >= MAX_CONFIGS: return
                        
                        host, port, sni, config_id = get_config_details(config)
                        if not host or host in seen_hosts: continue
                        if use_sni_filter and sni_domains and not any(d in sni for d in sni_domains): continue
                        if sni_counts.get(sni, 0) >= MAX_PER_SNI: continue
                        
                        try:
                            ip = socket.gethostbyname(host)
                            subnet = ".".join(ip.split(".")[:3])
                            if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
                            
                            # ГЕО проверка
                            geo = mmdb_reader.get(ip)
                            is_ru = geo and geo.get('country', {}).get('iso_code') == 'RU'
                            if is_ru and ru_count >= MAX_RU_CONFIGS: continue

                            # ИСПОЛЬЗУЕМ УМНЫЙ ПИНГ ВМЕСТО ОБЫЧНОГО
                            if smart_ping(ip, port, sni):
                                if is_ru: ru_count += 1
                                vlm2_list.append(config)
                                if "xhttp" not in config.lower(): vlm_list.append(config)
                                
                                seen_hosts.add(host)
                                sni_counts[sni] = sni_counts.get(sni, 0) + 1
                                subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                                id_counts[config_id] = id_counts.get(config_id, 0) + 1
                                print(f" [+] {host} | OK")
                        except: continue

        process_pool(extra_urls, True, "EXTRA")
        process_pool(std_urls, True, "STD")
        process_pool(extra_urls + std_urls, False, "RESERVE")

    # Сохранение на GitHub
    for name, lst in [(FILENAME_VLM, vlm_list), (FILENAME_VLM2, vlm2_list)]:
        if not lst: continue
        path = f"githubmirror/{name}"
        msg = f"🚀 {name} | T: {len(lst)} | {offset}"
        try:
            sha = REPO.get_contents(path).sha
            REPO.update_file(path, msg, "\n".join(lst), sha)
        except: REPO.create_file(path, msg, "\n".join(lst))

if __name__ == "__main__":
    main()
