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
    print(f"--- 🟢 ЗАПУСК СКРИПТА С ПРИОРИТЕТОМ SNI [{offset}] ---")
    
    # ЭТАП 1: Базы IP
    bad_networks += get_network_list(os.path.join(os.path.dirname(__file__), "cloudflare_ips.txt"), "https://www.cloudflare.com/ips-v4", "Cloudflare")
    bad_networks += get_network_list(os.path.join(os.path.dirname(__file__), "hetzner_ips.txt"), "https://raw.githubusercontent.com/ipverse/asn-networks/master/networks/AS24940.list", "Hetzner")
    bad_networks += get_network_list(os.path.join(os.path.dirname(__file__), "ocean_ips.txt"), "http://digitalocean.com/geo/google.csv", "DigitalOcean")

    # ЭТАП 2: Ресурсы
    try:
        src = session.get(REMOTE_SOURCE_URL).text
        def get_list_by_name(var_name):
            m = re.search(rf'{var_name}\s*=\s*\[(.*?)\]', src, re.S | re.I)
            return re.findall(r'["\']([^"\']+)["\']', m.group(1)) if m else []
        extra_urls = get_list_by_name("EXTRA_URLS_FOR_26")
        std_urls = get_list_by_name("URLS")
        sni_domains = set(s.lower() for s in get_list_by_name("SNI_DOMAINS"))
        print(f" [✓] Загружено {len(sni_domains)} приоритетных SNI.")
    except Exception as e:
        print(f" ❌ Ошибка Этапа 2: {e}"); return

    vlm_data, vlm2_data = {}, {}
    seen_ips, sni_counts, subnet_counts, id_counts = set(), {}, {}, {}
    ru_count = 0

    def validate_one_config(config, is_priority, white_sni_only):
        nonlocal ru_count
        if len(vlm2_data) >= MAX_CONFIGS and len(vlm_data) >= MAX_CONFIGS: return
        
        host, port, sni, cid, name = get_config_details(config)
        if not host or not sni: return

        # ФИЛЬТР ПО SNI (Новый функционал)
        is_white_sni = sni in sni_domains
        if white_sni_only and not is_white_sni: return
        if not white_sni_only and is_white_sni: return # Чтобы не дублировать проверки в разных проходах

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
                # Приоритет в итоговом списке (v=2 для Extra+Sni, v=1 для Extra)
                score = (2 if is_white_sni else 1) if is_priority else 0
                
                if len(vlm2_data) < MAX_CONFIGS:
                    vlm2_data[final_config] = score
                    added = True
                if "xhttp" not in final_config.lower() and len(vlm_data) < MAX_CONFIGS:
                    vlm_data[final_config] = score
                    added = True
                if added:
                    if is_ru: ru_count += 1
                    seen_ips.add(host)
                    subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                    id_counts[cid] = id_counts.get(cid, 0) + 1
                    sni_counts[sni] = sni_counts.get(sni, 0) + 1

    def process_step(urls, is_priority, white_sni_only):
        if len(vlm2_data) >= MAX_CONFIGS and len(vlm_data) >= MAX_CONFIGS: return
        
        mode = "WHITE SNI" if white_sni_only else "OTHER SNI"
        cat = "EXTRA" if is_priority else "STANDARD"
        print(f" > Поиск: {cat} + {mode}")
        
        all_raw = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as gatherer:
            futures = [gatherer.submit(fetch_raw_configs, u) for u in urls]
            for f in concurrent.futures.as_completed(futures):
                all_raw.extend(f.result())
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as validator:
            for config in all_raw:
                validator.submit(validate_one_config, config, is_priority, white_sni_only)

    # --- 4 УРОВНЯ ПРИОРИТЕТА ---
    process_step(extra_urls, True, True)   # 1. Extra + White SNI
    process_step(std_urls, False, True)    # 2. Standard + White SNI
    process_step(extra_urls, True, False)  # 3. Extra + Other SNI
    process_step(std_urls, False, False)   # 4. Standard + Other SNI

    def sort_configs(data_dict):
        # Сортируем по score (2, 1, 0)
        return [k for k, v in sorted(data_dict.items(), key=lambda item: item[1], reverse=True)]

    final_vlm, final_vlm2 = sort_configs(vlm_data), sort_configs(vlm2_data)

    try:
        g = Github(auth=Auth.Token(GITHUB_TOKEN))
        repo = g.get_repo(REPO_NAME)
        for fn, lst in [(FILENAME_VLM, final_vlm), (FILENAME_VLM2, final_vlm2)]:
            path = f"githubmirror/{fn}"
            msg = f"🚀 {fn} | T: {len(lst)} | RU: {ru_count} | {offset}"
            try:
                sha = repo.get_contents(path).sha
                repo.update_file(path, msg, "\n".join(lst), sha)
            except:
                repo.create_file(path, msg, "\n".join(lst))
    except Exception as e:
        print(f" ❌ GitHub Error: {e}")

    print(f"--- 🏁 ФИНИШ! Время: {time.perf_counter() - start_total:.2f} сек. ---")

if __name__ == "__main__":
    main()
