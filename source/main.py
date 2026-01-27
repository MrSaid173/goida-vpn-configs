import os, re, requests, urllib3, concurrent.futures, ipaddress, base64, json, time, socket, ssl
from datetime import datetime, timedelta
import zoneinfo
from github import Github, Auth
import maxminddb
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

RU_FLAG_EMOJI = "🇷🇺"
COUNTRY_MAP = {
    "RU": ["RUSSIA", "РОССИЯ", "RUS", RU_FLAG_EMOJI],
    "US": ["USA", "UNITED STATES", "AMERICA", "🇺🇸"],
    "DE": ["GERMANY", "ГЕРМАНИЯ", "DEUTSCHLAND", "🇩🇪"],
    "NL": ["NETHERLANDS", "НИДЕРЛАНДЫ", "HOLLAND", "🇳🇱"],
    "GB": ["UNITED KINGDOM", "ENGLAND", "🇬🇧"],
    "TR": ["TURKEY", "ТУРЦИЯ", "TURKIYE", "🇹🇷"],
    "KZ": ["KAZAKHSTAN", "КАЗАХСТАН", "🇰🇿"],
    "AT": ["AUSTRIA", "АВСТРИЯ", "🇦🇹"],
    "EE": ["ESTONIA", "ЭСТОНИЯ", "🇪🇪"],
    "LV": ["LATVIA", "ЛАТВИЯ", "LV-", "🇱🇻"],
    "FI": ["FINLAND", "ФИНЛЯНДИЯ", "🇫🇮"],
    "PL": ["POLAND", "ПОЛЬША", "🇵🇱"],
    "SE": ["SWEDEN", "ШВЕЦИЯ", "🇸🇪"],
    "FR": ["FRANCE", "ФРАНЦИЯ", "🇫🇷"],
    "IT": ["ITALY", "ИТАЛИЯ", "🇮🇹"],
    "ES": ["SPAIN", "ИСПАНИЯ", "🇪🇸"],
    "CA": ["CANADA", "КАНАДА", "🇨🇦"],
    "JP": ["JAPAN", "ЯПОНИЯ", "🇯🇵"],
    "HK": ["HONG KONG", "ГОНКОНГ", "🇭🇰"],
    "SG": ["SINGAPORE", "СИНГАПУР", "🇸🇬"],
}

lock = threading.Lock()

# --- УТИЛИТЫ ---

def get_cloudflare_networks():
    if os.path.exists(CF_IPS_PATH) and (datetime.now() - datetime.fromtimestamp(os.path.getmtime(CF_IPS_PATH)) < timedelta(days=3)):
        with open(CF_IPS_PATH, "r") as f: return [ipaddress.ip_network(l.strip()) for l in f if l.strip()]
    try:
        resp = session.get("https://www.cloudflare.com/ips-v4", timeout=10)
        with open(CF_IPS_PATH, "w") as f: f.write(resp.text)
        return [ipaddress.ip_network(l.strip()) for l in resp.text.splitlines() if l.strip()]
    except: return []

def check_isp_info(ip_str):
    """Проверка провайдера: исключаем хостинги и проверяем на RU."""
    try:
        time.sleep(1.35) 
        r = session.get(f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,isp,org,as", timeout=4).json()
        if r.get("status") == "success":
            isp_org_as = (str(r.get("isp", "")) + " " + str(r.get("org", "")) + " " + str(r.get("as", ""))).lower()
            
            # ЧЕРНЫЙ СПИСОК ХОСТИНГОВ
            bad_isps = ["cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google", "microsoft", "ovh", "linode", "m247", "leaseweb"]
            if any(x in isp_org_as for x in bad_isps):
                return False, True # Это хостинг
            
            is_ru = (r.get("countryCode") == "RU") or any(k in isp_org_as for k in ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota", "vimpelcom"])
            return is_ru, False # Не хостинг, статус RU определен
    except: pass
    return False, False

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
        if h_m:
            return h_m.group(1), int(h_m.group(2)), (s_m.group(1).lower() if s_m else ""), cid, name
    except: pass
    return None, None, None, None, None

def fetch_raw_configs(url):
    try:
        resp = session.get(url, timeout=12, verify=False).text
        if "://" not in resp[:50] and len(resp) > 64:
            try: resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
            except: pass
        text = re.sub(r'(vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', resp)
        return [l.strip() for l in text.splitlines() if "vless://" in l]
    except: return []

# --- ГЛАВНАЯ ЛОГИКА ---

def main():
    print(f"--- 🟢 ЗАПУСК СКРИПТА [{offset}] ---")
    
    if not os.path.exists(MMDB_PATH):
        try:
            r = requests.get(MMDB_URL, timeout=30)
            with open(MMDB_PATH, "wb") as f: f.write(r.content)
        except: pass
    cf_networks = get_cloudflare_networks()

    # [2] ЗАГРУЗКА ИСТОЧНИКОВ И SNI
    try:
        src = session.get(REMOTE_SOURCE_URL).text
        
        # Улучшенный парсинг списков URL
        def get_list(n):
            m = re.search(rf'{n}\s*=\s*\[(.*?)\]', src, re.S)
            if not m: return []
            return re.findall(r'["\'](https?://[^"\']+)["\']', m.group(1))
        
        extra_urls = get_list("EXTRA_URLS_FOR_26")
        std_urls = get_list("URLS")
        
        # Улучшенный парсинг SNI_DOMAINS
        sni_match = re.search(r'SNI_DOMAINS\s*=\s*\[(.*?)\]', src, re.S)
        if sni_match:
            # Извлекаем все строки внутри кавычек
            sni_domains = re.findall(r'["\']([^"\']+)["\']', sni_match.group(1))
            sni_domains = [s.lower() for s in sni_domains]
        else:
            sni_domains = []
            
        print(f" [✓] Источники загружены. SNI в базе: {len(sni_domains)}")
    except Exception as e:
        print(f" ❌ Ошибка загрузки: {e}"); return

    vlm_list, vlm2_list = [], []
    seen_hosts, seen_ips, sni_counts, subnet_counts, id_counts = set(), set(), {}, {}, {}
    ru_count = 0

    with maxminddb.open_database(MMDB_PATH) as reader:
        def process_pool(urls, use_sni_filter, stage_name):
            nonlocal ru_count
            print(f"\n--- 🛰 ЭТАП: {stage_name} ---")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=35) as executor:
                f_to_u = {executor.submit(fetch_raw_configs, u): u for u in urls}
                for f in concurrent.futures.as_completed(f_to_u):
                    for config in f.result():
                        if len(vlm2_list) >= MAX_CONFIGS and len(vlm_list) >= MAX_CONFIGS: return
                        
                        host, port, sni, cid, name = get_config_details(config)
                        if not host or not sni or host in seen_hosts: continue
                        
                        # 1. ТОЛЬКО IP
                        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host): continue
                        
                        # 2. ФИЛЬТР SNI (проверка наличия в списке из основного кода)
                        sni_lower = sni.lower()
                        if use_sni_filter:
                            if not any(d in sni_lower for d in sni_domains): continue
                        
                        # 3. ИСКЛЮЧЕНИЕ ГРЯЗИ В НАЗВАНИИ И SNI
                        name_lower = name.lower()
                        if any(x in name_lower or x in sni_lower for x in ["cloudflare", "openproxy", "hero", "panel"]): continue
                        
                        # 4. ЛИМИТЫ
                        with lock:
                            if sni_counts.get(sni_lower, 0) >= MAX_PER_SNI or id_counts.get(cid, 0) >= MAX_PER_ID: continue

                        try:
                            ip = host
                            if ip in seen_ips: continue
                            
                            # Проверка Cloudflare сетей
                            ip_obj = ipaddress.ip_address(ip)
                            if any(ip_obj in net for net in cf_networks): continue

                            subnet = ".".join(ip.split(".")[:3])
                            with lock:
                                if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
                            
                            # ГЕО ИЗ MMDB
                            geo = reader.get(ip)
                            ip_country = geo.get('country', {}).get('iso_code', '').upper() if geo else ""
                            
                            # --- ЛОГИКА СРАВНЕНИЯ С COUNTRY_MAP ---
                            name_up = name.upper()
                            
                            # Проверяем, не принадлежит ли конфиг другой стране (несовпадение флага и IP)
                            mismatch = False
                            for code, aliases in COUNTRY_MAP.items():
                                if any(alias in name_up for alias in aliases):
                                    if ip_country and ip_country != code:
                                        mismatch = True # Написано US, а IP из DE
                                        break
                            if mismatch: continue

                            # Определение RU статуса
                            is_ru_by_name = RU_FLAG_EMOJI in name or any(word in name_up for word in ["RU", "RUSSIA", "РОССИЯ", "RUS"])
                            is_ru_by_ip = (ip_country == 'RU')
                            
                            # ПРОВЕРКА ПРОВАЙДЕРА (ИСКЛЮЧЕНИЕ HETZNER/DIGITALOCEAN И Т.Д.)
                            is_ru_isp, is_bad_hosting = check_isp_info(ip)
                            if is_bad_hosting: continue # Сразу выкидываем хостинги

                            # Финальное решение по RU
                            is_final_ru = (is_ru_by_name or is_ru_by_ip or is_ru_isp)
                            
                            if is_final_ru:
                                with lock:
                                    if ru_count >= MAX_RU_CONFIGS: continue

                            # ПИНГ
                            if smart_ping(ip, port, sni):
                                with lock:
                                    if is_final_ru: ru_count += 1
                                    
                                    added = False
                                    if len(vlm2_list) < MAX_CONFIGS:
                                        vlm2_list.append(config); added = True
                                    if "xhttp" not in config.lower() and len(vlm_list) < MAX_CONFIGS:
                                        vlm_list.append(config); added = True
                                    
                                    if added:
                                        seen_hosts.add(host); seen_ips.add(ip)
                                        sni_counts[sni_lower] = sni_counts.get(sni_lower, 0) + 1
                                        subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                                        id_counts[cid] = id_counts.get(cid, 0) + 1
                                        print(f" [+] {ip} ({ip_country}) | RU: {is_final_ru} | {name[:20]}")
                        except: continue

        process_pool(extra_urls, True, "EXTRA_PRIORITY")
        process_pool(std_urls, True, "STD_PRIORITY")
        process_pool(extra_urls + std_urls, False, "RESERVE_ALL")

    # [3] СОХРАНЕНИЕ
    try:
        g = Github(auth=Auth.Token(GITHUB_TOKEN))
        repo = g.get_repo(REPO_NAME)
        for fn, lst in [(FILENAME_VLM, vlm_list), (FILENAME_VLM2, vlm2_list)]:
            if not lst: continue
            path = f"githubmirror/{fn}"
            msg = f"🚀 {fn} | T: {len(lst)} | RU: {ru_count} | {offset}"
            try:
                sha = repo.get_contents(path).sha
                repo.update_file(path, msg, "\n".join(lst), sha)
            except:
                repo.create_file(path, msg, "\n".join(lst))
    except Exception as e:
        print(f" ❌ Ошибка GitHub: {e}")

    total_time = time.perf_counter() - start_exec_time
    print(f"\n--- 🏁 ФИНИШ! RU: {ru_count} | Всего: {len(vlm2_list)} ---")

if __name__ == "__main__":
    main()
