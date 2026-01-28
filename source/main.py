import os, re, requests, urllib3, concurrent.futures, ipaddress, base64, json, time, socket, ssl
from datetime import datetime, timedelta
import zoneinfo
from github import Github, Auth
import threading

# --- НАСТРОЙКИ (без изменений) ---
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MrSaid173/golden-paths_configs"
FILENAME_VLM = "vlm"
FILENAME_VLM2 = "vlm2"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
MMDB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

MAX_CONFIGS = 150 
MAX_RU_CONFIGS = 6
MAX_PER_SUBNET = 3 
MAX_PER_SNI = 15
MAX_PER_ID = 3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
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
api_semaphore = threading.Semaphore(3)
bad_networks = []

# --- УТИЛИТЫ ---

def apply_random_fp(config_link):
    return re.sub(r'fp=[^&?#]+', 'fp=random', config_link)

def get_network_list(file_path, url, name):
    if os.path.exists(file_path) and (datetime.now() - datetime.fromtimestamp(os.path.getmtime(file_path)) < timedelta(days=3)):
        try:
            with open(file_path, "r") as f: 
                return [ipaddress.ip_network(l.strip()) for l in f if l.strip()]
        except: pass
    try:
        resp = session.get(url, timeout=15)
        found_ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?', resp.text)
        if found_ips:
            with open(file_path, "w") as f: f.write("\n".join(found_ips))
            return [ipaddress.ip_network(ip) for ip in found_ips]
    except: pass
    return []

def check_isp_info(ip_str):
    with api_semaphore:
        try:
            time.sleep(1.4)
            r = session.get(f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,isp,org,as", timeout=5).json()
            if r.get("status") == "success":
                isp_info = (str(r.get("isp", "")) + " " + str(r.get("org", "")) + " " + str(r.get("as", ""))).lower()
                country = r.get("countryCode", "")
                bad_keywords = ["cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google", "microsoft", "ovh", "linode"]
                is_hosting = any(x in isp_info for x in bad_keywords)
                return country, isp_info, is_hosting
        except: pass
        return None, None, False

def smart_ping(host, port, sni):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=1.1) as sock:
            with context.wrap_socket(sock, server_hostname=sni): return True
    except: return False

def get_config_details(link):
    try:
        name = requests.utils.unquote(link.split("#")[1]) if "#" in link else ""
        clean_link = re.sub(r'[^\x20-\x7E]', '', link).strip()
        id_match = re.search(r'://([^@]+)@', clean_link)
        cid = id_match.group(1) if id_match else None
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', clean_link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', clean_link)
        sni = s_m.group(1).lower() if s_m else ""
        if h_m:
            return h_m.group(1), int(h_m.group(2)), sni, cid, name
    except: pass
    return None, None, None, None, None

def fetch_raw_configs(url):
    try:
        resp = session.get(url, timeout=12, verify=False).text
        if "://" not in resp[:50] and len(resp) > 64:
            try: resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
            except: pass
        all_links = re.findall(r'(?:vless|ssr|tuic|hysteria|hysteria2)://[^\s]+', resp)
        return [l.strip() for l in all_links if not l.startswith(("ss://", "trojan://"))]
    except: return []

# --- ГЛАВНАЯ ЛОГИКА ---

def main():
    global bad_networks
    start_total = time.perf_counter()
    print(f"--- 🟢 ЗАПУСК СКРИПТА [{offset}] ---")
    
    # ЭТАП 1: Инициализация баз
    s_init = time.perf_counter()
    bad_networks += get_network_list(os.path.join(os.path.dirname(__file__), "cloudflare_ips.txt"), "https://www.cloudflare.com/ips-v4", "Cloudflare")
    bad_networks += get_network_list(os.path.join(os.path.dirname(__file__), "hetzner_ips.txt"), "https://raw.githubusercontent.com/ipverse/asn-networks/master/networks/AS24940.list", "Hetzner")
    bad_networks += get_network_list(os.path.join(os.path.dirname(__file__), "ocean_ips.txt"), "http://digitalocean.com/geo/google.csv", "DigitalOcean")
    print(f" [⏱] Этап 1 (Базы IP) завершен за {time.perf_counter() - s_init:.2f} сек.")

    # ЭТАП 2: Получение URL источников
    s_src = time.perf_counter()
    try:
        src = session.get(REMOTE_SOURCE_URL).text
        def get_list_by_name(var_name):
            m = re.search(rf'{var_name}\s*=\s*\[(.*?)\]', src, re.S | re.I)
            return re.findall(r'["\']([^"\']+)["\']', m.group(1)) if m else []
        extra_urls = get_list_by_name("EXTRA_URLS_FOR_26")
        std_urls = get_list_by_name("URLS")
        print(f" [⏱] Этап 2 (Импорт ресурсов) завершен за {time.perf_counter() - s_src:.2f} сек.")
    except Exception as e:
        print(f" ❌ Ошибка Этапа 2: {e}"); return

    vlm_data, vlm2_data = {}, {}
    seen_ips, sni_counts, subnet_counts, id_counts = set(), {}, {}, {}
    ru_count = 0

    def validate_one_config(config, is_priority):
        nonlocal ru_count
        if len(vlm2_data) >= MAX_CONFIGS and len(vlm_data) >= MAX_CONFIGS: return
        host, port, sni, cid, name = get_config_details(config)
        if not host or not sni: return
        garbage = ["cloudflare", "openproxy", "-udp443"]
        if any(x in name.lower() or x in sni.lower() for x in garbage): return
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host): return 
        with lock:
            if host in seen_ips: return
            subnet = ".".join(host.split(".")[:3])
            if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET or \
               id_counts.get(cid, 0) >= MAX_PER_ID or \
               sni_counts.get(sni, 0) >= MAX_PER_SNI: return
        try:
            ip_obj = ipaddress.ip_address(host)
            if any(ip_obj in net for net in bad_networks): return
        except: return
        country_code, isp_info, is_hosting = check_isp_info(host)
        if not country_code or is_hosting: return
        mismatch = False
        for code, aliases in COUNTRY_MAP.items():
            if any(a in name.upper() for a in aliases) and country_code != code:
                mismatch = True; break
        if mismatch: return
        is_ru = (country_code == "RU")
        with lock:
            if is_ru and ru_count >= MAX_RU_CONFIGS: return
        if smart_ping(host, port, sni):
            final_config = apply_random_fp(config)
            with lock:
                added = False
                if len(vlm2_data) < MAX_CONFIGS:
                    vlm2_data[final_config] = is_priority
                    added = True
                if "xhttp" not in final_config.lower() and len(vlm_data) < MAX_CONFIGS:
                    vlm_data[final_config] = is_priority
                    added = True
                if added:
                    if is_ru: ru_count += 1
                    seen_ips.add(host)
                    subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                    id_counts[cid] = id_counts.get(cid, 0) + 1
                    sni_counts[sni] = sni_counts.get(sni, 0) + 1

    def process_category(urls, is_priority):
        cat_name = 'EXTRA' if is_priority else 'STANDARD'
        s_cat = time.perf_counter()
        print(f"\n--- 🚀 ОБРАБОТКА: {cat_name} ---")
        
        # Сбор ссылок
        s_fetch = time.perf_counter()
        all_raw = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as gatherer:
            futures = [gatherer.submit(fetch_raw_configs, u) for u in urls]
            for f in concurrent.futures.as_completed(futures):
                all_raw.extend(f.result())
        print(f" [⏱] Сбор {len(all_raw)} ссылок ({cat_name}) занял {time.perf_counter() - s_fetch:.2f} сек.")
        
        # Валидация
        s_val = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as validator:
            for config in all_raw:
                if len(vlm2_data) >= MAX_CONFIGS and len(vlm_data) >= MAX_CONFIGS: break
                validator.submit(validate_one_config, config, is_priority)
        print(f" [⏱] Валидация в категории {cat_name} завершена за {time.perf_counter() - s_val:.2f} сек.")

    # Запуск категорий
    process_category(extra_urls, True)
    if len(vlm2_data) < MAX_CONFIGS or len(vlm_data) < MAX_CONFIGS:
        process_category(std_urls, False)

    # ЭТАП 7: Сортировка и Публикация
    s_pub = time.perf_counter()
    def sort_configs(data_dict):
        return [k for k, v in sorted(data_dict.items(), key=lambda item: item[1], reverse=True)]

    final_vlm, final_vlm2 = sort_configs(vlm_data), sort_configs(vlm2_data)

    try:
        g = Github(auth=Auth.Token(GITHUB_TOKEN))
        repo = g.get_repo(REPO_NAME)
        for fn, lst in [(FILENAME_VLM, final_vlm), (FILENAME_VLM2, final_vlm2)]:
            path = f"githubmirror/{fn}"
            content = "\n".join(lst)
            msg = f"🚀 {fn} | T: {len(lst)} | RU: {ru_count} | {offset}"
            try:
                sha = repo.get_contents(path).sha
                repo.update_file(path, msg, content, sha)
            except:
                repo.create_file(path, msg, content)
        print(f"\n [⏱] Этап публикации на GitHub занял {time.perf_counter() - s_pub:.2f} сек.")
    except Exception as e:
        print(f" ❌ GitHub Error: {e}")

    total_time = time.perf_counter() - start_total
    print(f"\n--- 🏁 ГОТОВО! Всего: {len(final_vlm2)} | RU: {ru_count}")
    print(f"--- ⏱ ОБЩЕЕ ВРЕМЯ РАБОТЫ: {total_time:.2f} сек. ---")

if __name__ == "__main__":
    main()
