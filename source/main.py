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
start_exec_time = time.perf_counter() # Глобальный таймер
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")

RU_FLAG_EMOJI = "🇷🇺"
# Карта стран (сохранена из твоего кода)
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
    try:
        time.sleep(1.35) # Лимит для API
        r = session.get(f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,isp,org", timeout=4).json()
        if r.get("status") == "success":
            isp_org = (str(r.get("isp", "")) + " " + str(r.get("org", ""))).lower()
            bad_isps = ["cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google", "microsoft"]
            if any(x in isp_org for x in bad_isps): return False, True
            is_ru = (r.get("countryCode") == "RU") or any(k in isp_org for k in ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota"])
            return is_ru, False
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
    
    # [1] ПОДГОТОВКА БАЗ
    stage_start = time.perf_counter()
    if not os.path.exists(MMDB_PATH):
        try:
            r = requests.get(MMDB_URL, timeout=30)
            with open(MMDB_PATH, "wb") as f: f.write(r.content)
        except: pass
    cf_networks = get_cloudflare_networks()
    print(f" [✓] Этап 1 (Базы): {time.perf_counter()-stage_start:.2f} сек.")

    # [2] ЗАГРУЗКА ИСТОЧНИКОВ
    stage_start = time.perf_counter()
    try:
        src = session.get(REMOTE_SOURCE_URL).text
        def get_list(n):
            m = re.search(rf'{n}\s*=\s*\[(.*?)\]', src, re.S)
            return re.findall(r'["\'](https?://[^"\']+)["\']', m.group(1)) if m else []
        extra_urls, std_urls = get_list("EXTRA_URLS_FOR_26"), get_list("URLS")
        sni_match = re.search(r'SNI_DOMAINS\s*=\s*\[(.*?)\]', src, re.S)
        sni_domains = [s.strip(" \"'").lower() for s in sni_match.group(1).split(",")] if sni_match else []
    except Exception as e:
        print(f" ❌ Ошибка на этапе 2: {e}"); return
    print(f" [✓] Этап 2 (Источники): {time.perf_counter()-stage_start:.2f} сек.")

    vlm_list, vlm2_list = [], []
    seen_hosts, seen_ips, sni_counts, subnet_counts, id_counts = set(), set(), {}, {}, {}
    ru_count = 0

    with maxminddb.open_database(MMDB_PATH) as reader:
        def process_pool(urls, use_sni_filter, stage_name):
            nonlocal ru_count
            print(f"\n--- 🛰 ЭТАП: {stage_name} ---")
            st_stage = time.perf_counter()
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=35) as executor:
                f_to_u = {executor.submit(fetch_raw_configs, u): u for u in urls}
                for f in concurrent.futures.as_completed(f_to_u):
                    for config in f.result():
                        if len(vlm2_list) >= MAX_CONFIGS and len(vlm_list) >= MAX_CONFIGS: break
                        
                        host, port, sni, cid, name = get_config_details(config)
                        
                        # 1. ОБЯЗАТЕЛЬНОЕ НАЛИЧИЕ SNI И ЧИСТЫЙ ХОСТ
                        if not host or not sni: continue
                        if host in seen_hosts: continue
                        
                        # 2. ИСКЛЮЧЕНИЕ БУКВЕННЫХ ХОСТОВ (ТОЛЬКО ЦИФРОВЫЕ IP)
                        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host): continue
                        
                        # 3. ФИЛЬТР ПО ИМЕНИ (Исключаем cloudflare/openproxy везде в названии)
                        name_lower = name.lower()
                        if any(x in name_lower for x in ["cloudflare", "openproxy"]): continue
                        
                        # 3.1 ФИЛЬТР SNI (CLOUDFLARE / OPENPROXY ИСКЛЮЧЕНИЕ)
                        sni_lower = sni.lower()
                        if any(x in sni_lower for x in ["cloudflare", "openproxy"]): continue
                        
                        # 4. ФИЛЬТР ПРИОРИТЕТНЫХ SNI
                        if use_sni_filter and not any(d in sni_lower for d in sni_domains): continue
                        
                        # 5. ЛИМИТЫ ПО SNI И ID
                        with lock:
                            if sni_counts.get(sni, 0) >= MAX_PER_SNI or id_counts.get(cid, 0) >= MAX_PER_ID: continue

                        try:
                            ip = host 
                            if ip in seen_ips: continue
                            
                            # Проверка сетей Cloudflare (по IP)
                            ip_obj = ipaddress.ip_address(ip)
                            if any(ip_obj in net for net in cf_networks): continue

                            # 6. ФИЛЬТР ПО ПОДСЕТИ
                            subnet = ".".join(ip.split(".")[:3])
                            with lock:
                                if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
                            
                            geo = reader.get(ip)
                            ip_country = geo.get('country', {}).get('iso_code', '').upper() if geo else ""
                            
                            # Определение RU
                            name_up = name.upper()
                            is_ru_by_name = RU_FLAG_EMOJI in name or any(word in name_up for word in ["RU", "RUSSIA", "РОССИЯ", "RUS"])
                            is_ru_by_ip = (ip_country == 'RU')
                            is_ru_candidate = is_ru_by_name or is_ru_by_ip

                            # 9. Проверка провайдера (Исключение хостингов)
                            is_ru_confirmed, is_bad_isp = check_isp_info(ip)
                            if is_bad_isp: continue

                            if is_ru_candidate:
                                with lock:
                                    if ru_count >= MAX_RU_CONFIGS: is_ru_candidate = False
                            
                            if smart_ping(ip, port, sni):
                                with lock:
                                    is_final_ru = is_ru_candidate and (is_ru_by_name or is_ru_confirmed)
                                    if is_final_ru: ru_count += 1
                                    
                                    added = False
                                    if len(vlm2_list) < MAX_CONFIGS:
                                        vlm2_list.append(config); added = True
                                    if "xhttp" not in config.lower() and len(vlm_list) < MAX_CONFIGS:
                                        vlm_list.append(config); added = True
                                    
                                    if added:
                                        seen_hosts.add(host); seen_ips.add(ip)
                                        sni_counts[sni] = sni_counts.get(sni, 0) + 1
                                        subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                                        id_counts[cid] = id_counts.get(cid, 0) + 1
                                        print(f" [+] {ip} | RU: {is_final_ru} | {name[:20]}")
                        except: continue
            
            print(f" [✓] Этап {stage_name} завершен за {time.perf_counter()-st_stage:.2f} сек.")

        # ЗАПУСК ЭТАПОВ
        process_pool(extra_urls, True, "EXTRA_PRIORITY")
        process_pool(std_urls, True, "STD_PRIORITY")
        process_pool(extra_urls + std_urls, False, "RESERVE_ALL")

    # [3] СОХРАНЕНИЕ
    print(f"\n--- 📤 ЭТАП: GITHUB UPLOAD ---")
    stage_start = time.perf_counter()
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
        print(f" [✓] Этап 3 (Upload): {time.perf_counter()-stage_start:.2f} сек.")
    except Exception as e:
        print(f" ❌ Ошибка GitHub: {e}")

    total_time = time.perf_counter() - start_exec_time
    print(f"\n--- 🏁 ФИНИШ! RU: {ru_count} | Всего: {len(vlm2_list)} ---")
    print(f" ОБЩЕЕ ВРЕМЯ РАБОТЫ: {total_time/60:.2f} мин. ({int(total_time)} сек.)")

if __name__ == "__main__":
    main()
