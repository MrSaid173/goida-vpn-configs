import os, re, requests, urllib3, concurrent.futures, ipaddress, base64, json, time, socket, ssl
from datetime import datetime, timedelta
import zoneinfo
from github import Github, Auth
import threading

# --- НАСТРОЙКИ ---
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MrSaid173/golden-paths_configs"
FILENAME_VLM = "vlm"
FILENAME_VLM2 = "vlm2"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
MMDB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MMDB_PATH = os.path.join(BASE_DIR, "GeoLite2-Country.mmdb")
CF_IPS_PATH = os.path.join(BASE_DIR, "cloudflare_ips.txt")
HZ_IPS_PATH = os.path.join(BASE_DIR, "hetzner_ips.txt")
DO_IPS_PATH = os.path.join(BASE_DIR, "ocean_ips.txt")

MAX_CONFIGS = 150 
MAX_RU_CONFIGS = 6
MAX_PER_SUBNET = 3 
MAX_PER_SNI = 15
MAX_PER_ID = 3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
start_exec_time = time.perf_counter()
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")

COUNTRY_MAP = {
    "RU": ["RUSSIA", "РОССИЯ", "RUS", "🇷🇺"],
    "US": ["USA", "UNITED STATES", "AMERICA", "🇺🇸"],
    "DE": ["GERMANY", "ГЕРМАНИЯ", "DEUTSCHLAND", "🇩🇪"],
    "NL": ["NETHERLANDS", "НИДЕРЛАНДЫ", "HOLLAND", "🇳🇱"],
    "GB": ["UNITED KINGDOM", "ENGLAND", "🇬🇧"],
    "TR": ["TURKEY", "ТУРЦИЯ", "TURKIYE", "🇹🇷"],
    "KZ": ["KAZAKHSTAN", "КАЗАХСТАН", "🇰🇿"],
    "FI": ["FINLAND", "ФИНЛЯНДИЯ", "🇫🇮"],
    "PL": ["POLAND", "ПОЛЬША", "🇵🇱"],
}

lock = threading.Lock()
bad_networks = [] # Глобальный список заблокированных сетей (CF, Hetzner, DO)

# --- ЭТАП 1: УТИЛИТЫ И ИНИЦИАЛИЗАЦИЯ ---

def get_network_list(file_path, url, name):
    """Универсальная загрузка списков IP хостингов (Этап 1 & 4)"""
    if os.path.exists(file_path) and (datetime.now() - datetime.fromtimestamp(os.path.getmtime(file_path)) < timedelta(days=3)):
        try:
            with open(file_path, "r") as f: 
                return [ipaddress.ip_network(l.strip()) for l in f if l.strip()]
        except: pass
    try:
        print(f" [!] Обновление базы {name}...")
        resp = session.get(url, timeout=15)
        # Извлекаем все IP/CIDR из текста (подходит для разных форматов)
        found_ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?', resp.text)
        if found_ips:
            with open(file_path, "w") as f: f.write("\n".join(found_ips))
            return [ipaddress.ip_network(ip) for ip in found_ips]
    except Exception as e:
        print(f" ❌ Ошибка загрузки {name}: {e}")
    return []

def check_isp_info(ip_str):
    """Этап 4: Онлайн проверка через ip-api.com"""
    try:
        time.sleep(1.4) # Строго 1.4 секунды по ТЗ
        r = session.get(f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,isp,org,as", timeout=5).json()
        if r.get("status") == "success":
            isp_info = (str(r.get("isp", "")) + " " + str(r.get("org", "")) + " " + str(r.get("as", ""))).lower()
            country = r.get("countryCode", "")
            # Финальный онлайн-фильтр хостингов (на случай, если IP нет в локальных базах)
            bad_keywords = ["cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google", "microsoft", "ovh", "linode", "m247", "leaseweb"]
            is_hosting = any(x in isp_info for x in bad_keywords)
            return country, isp_info, is_hosting
    except: pass
    return None, None, False

def smart_ping(host, port, sni):
    """Этап 5: TLS-пинг"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=1.1) as sock:
            with context.wrap_socket(sock, server_hostname=sni): return True
    except: return False

def get_config_details(link):
    """Этап 3: Парсинг запчастей"""
    try:
        name = requests.utils.unquote(link.split("#")[1]) if "#" in link else ""
        clean_link = re.sub(r'[^\x20-\x7E]', '', link).strip()
        id_match = re.search(r'://([^@]+)@', clean_link)
        cid = id_match.group(1) if id_match else None
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', clean_link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', clean_link)
        if h_m:
            return h_m.group(1), int(h_m.group(2)), (s_m.group(1).lower() if s_m else ""), cid, name
    except: pass
    return None, None, None, None, None

def fetch_raw_configs(url):
    """Этап 2: Сбор и расшифровка"""
    try:
        resp = session.get(url, timeout=12, verify=False).text
        if "://" not in resp[:50] and len(resp) > 64:
            try: resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
            except: pass
        # Вытаскиваем все, кроме trojan и ss (Этап 2)
        all_links = re.findall(r'(?:vless|ssr|tuic|hysteria|hysteria2)://[^\s]+', resp)
        return [l.strip() for l in all_links if not l.startswith(("ss://", "trojan://"))]
    except: return []

# --- ГЛАВНАЯ ЛОГИКА ---

def main():
    global bad_networks
    print(f"--- 🟢 ЗАПУСК СКРИПТА [{offset}] ---")
    
    # Ресурсы: GeoLite2 (Этап 1)
    if not os.path.exists(MMDB_PATH) or (datetime.now() - datetime.fromtimestamp(os.path.getmtime(MMDB_PATH)) > timedelta(days=3)):
        try:
            r = requests.get(MMDB_URL, timeout=30)
            with open(MMDB_PATH, "wb") as f: f.write(r.content)
        except: pass
    
    # Загрузка локальных баз "плохих" сетей (Этап 1 & 4)
    bad_networks += get_network_list(CF_IPS_PATH, "https://www.cloudflare.com/ips-v4", "Cloudflare")
    bad_networks += get_network_list(HZ_IPS_PATH, "https://raw.githubusercontent.com/ipverse/asn-networks/master/networks/AS24940.list", "Hetzner")
    bad_networks += get_network_list(DO_IPS_PATH, "http://digitalocean.com/geo/google.csv", "DigitalOcean")

    # Списки SNI (Этап 1)
    try:
        sni_start_time = time.perf_counter()
        src = session.get(REMOTE_SOURCE_URL).text
        
        def get_list_by_name(var_name):
            # Регистронезависимый поиск (re.I)
            m = re.search(rf'{var_name}\s*=\s*\[(.*?)\]', src, re.S | re.I)
            return re.findall(r'["\']([^"\']+)["\']', m.group(1)) if m else []

        extra_urls = get_list_by_name("EXTRA_URLS_FOR_26")
        std_urls = get_list_by_name("URLS")
        sni_domains = [s.lower() for s in get_list_by_name("SNI_DOMAINS")]
        
        print(f" [✓] SNI загружены за {time.perf_counter() - sni_start_time:.2f}с. Первые 5: {sni_domains[:5]}")
    except Exception as e:
        print(f" ❌ Ошибка Этапа 1/2: {e}"); return

    vlm_list, vlm2_list = [], []
    seen_ips, sni_counts, subnet_counts, id_counts = set(), {}, {}, {}
    ru_count = 0

    def process_pool(urls, stage_name):
        nonlocal ru_count
        print(f"\n--- 🛰 ЭТАП 2/3: {stage_name} ---")
        
        raw_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor: # 20 потоков (Этап 3)
            futures = {executor.submit(fetch_raw_configs, u): u for u in urls}
            for f in concurrent.futures.as_completed(futures):
                configs = f.result()
                raw_count += len(configs)
                
                for config in configs:
                    if len(vlm2_list) >= MAX_CONFIGS: break
                    
                    # 1. Парсинг
                    host, port, sni, cid, name = get_config_details(config)
                    if not host or not sni: continue
                    
                    # 2. Первичный отсев
                    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host): continue 
                    
                    name_low = name.lower()
                    if any(x in name_low for x in ["openproxy", "cloudflare", "-udp443"]): continue # Грязь
                    
                    # 3. Лимиты и уникальность
                    if host in seen_ips: continue
                    subnet = ".".join(host.split(".")[:3])
                    
                    with lock:
                        if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
                        if id_counts.get(cid, 0) >= MAX_PER_ID: continue
                        if sni_counts.get(sni, 0) >= MAX_PER_SNI: continue

                    # 4. Гео-проверка и аудит (Локальный + Онлайн)
                    try:
                        ip_obj = ipaddress.ip_address(host)
                        # Быстрая локальная проверка по базам CF/HZ/DO
                        if any(ip_obj in net for net in bad_networks): continue
                    except: continue

                    # Онлайн проверка (ip-api)
                    country_code, isp_info, is_hosting = check_isp_info(host)
                    if not country_code or is_hosting: continue
                    
                    # Детектор лжи
                    mismatch = False
                    name_up = name.upper()
                    for code, aliases in COUNTRY_MAP.items():
                        if any(a in name_up for a in aliases) and country_code != code:
                            mismatch = True; break
                    if mismatch: continue

                    # 5. Проверка связи и RU лимит
                    is_ru = (country_code == "RU")
                    if is_ru and ru_count >= MAX_RU_CONFIGS: continue
                    
                    if smart_ping(host, port, sni):
                        with lock:
                            if is_ru: ru_count += 1
                            seen_ips.add(host)
                            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                            id_counts[cid] = id_counts.get(cid, 0) + 1
                            sni_counts[sni] = sni_counts.get(sni, 0) + 1
                            
                            vlm2_list.append(config)
                            if "xhttp" not in config.lower():
                                vlm_list.append(config)
                            print(f" [+] {host} | {country_code} | {isp_info[:30]}")

        print(f" [i] Найдено сырых конфигов на этапе {stage_name}: {raw_count}")

    process_pool(extra_urls, "EXTRA_PRIORITY")
    process_pool(std_urls, "STD_PRIORITY")

    # --- ЭТАП 7: ПУБЛИКАЦИЯ ---
    try:
        g = Github(auth=Auth.Token(GITHUB_TOKEN))
        repo = g.get_repo(REPO_NAME)
        for fn, lst in [(FILENAME_VLM, vlm_list), (FILENAME_VLM2, vlm2_list)]:
            if not lst: continue
            path = f"githubmirror/{fn}"
            msg = f"🚀 {fn} | T: {len(lst)} | RU: {ru_count} | {offset}"
            content = "\n".join(lst)
            try:
                sha = repo.get_contents(path).sha
                repo.update_file(path, msg, content, sha)
            except:
                repo.create_file(path, msg, content)
        print(f"--- 🏁 ФИНИШ! Всего: {len(vlm2_list)} | RU: {ru_count} ---")
    except Exception as e:
        print(f" ❌ Ошибка GitHub: {e}")

if __name__ == "__main__":
    main()
