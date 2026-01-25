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
FILENAME_OPT = "opt.json"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
MMDB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
HZ_SOURCE_URL = "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/24940/ipv4-aggregated.txt"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MMDB_PATH = os.path.join(BASE_DIR, "GeoLite2-Country.mmdb")
CF_IPS_PATH = os.path.join(BASE_DIR, "cloudflare_ips.txt")
HZ_IPS_PATH = os.path.join(BASE_DIR, "hetzner_ips.txt")

MAX_CONFIGS = 10 
MAX_RU_CONFIGS = 5 
MAX_PER_SUBNET = 3 
MAX_PER_SNI = 15
MAX_PER_ID = 3
MIN_RU_PING = 110.0
MAX_RU_PING = 450.0

RU_PATTERN = [2, 5, 3, 5] 

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
now_moscow = datetime.now(zone)
offset = now_moscow.strftime("%H:%M | %d.%m.%Y")

# --- ПОЛНЫЙ COUNTRY_MAP ---
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

# Блокировка для потокобезопасности
lock = threading.Lock()

# --- УТИЛИТЫ ---

def get_net_list(path, url):
    if os.path.exists(path) and (datetime.now() - datetime.fromtimestamp(os.path.getmtime(path)) < timedelta(days=3)):
        with open(path, "r") as f: return [ipaddress.ip_network(l.strip()) for l in f if "/" in l]
    try:
        r = requests.get(url, timeout=10)
        with open(path, "w") as f: f.write(r.text)
        return [ipaddress.ip_network(l.strip()) for l in r.text.splitlines() if "/" in l]
    except: return []

def check_isp_online(ip):
    try:
        # IP-API имеет лимит 45 запросов в минуту. В многопотоке может быть затык, 
        # но мы вызываем его только после всех остальных фильтров.
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,countryCode,isp,org", timeout=4).json()
        if r.get("status") == "success":
            info = (str(r.get("isp", "")) + " " + str(r.get("org", ""))).lower()
            if any(x in info for x in ["cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google", "microsoft", "ovh"]):
                return False, True 
            is_ru = (r.get("countryCode") == "RU") or any(k in info for k in ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota"])
            return is_ru, False
    except: pass
    return False, False

def smart_ping(host, port, sni):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=1.1) as s:
            with ctx.wrap_socket(s, server_hostname=sni): return True
    except: return False

def get_triple_ping(host, port, sni):
    lats = []
    for _ in range(3):
        start = time.perf_counter()
        if smart_ping(host, port, sni):
            lats.append((time.perf_counter() - start) * 1000)
        time.sleep(0.4) 
    return min(lats) if lats else None

def get_config_details(link):
    try:
        name = requests.utils.unquote(link.split("#")[1]) if "#" in link else ""
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', link)
        id_m = re.search(r'://([^@]+)@', link)
        if h_m: return h_m.group(1), int(h_m.group(2)), (s_m.group(1).lower() if s_m else ""), (id_m.group(1) if id_m else ""), name
    except: pass
    return None, None, None, None, None

def fetch_raw(url):
    try:
        resp = session.get(url, timeout=12, verify=False).text
        if "://" not in resp[:50]:
            try: resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
            except: pass
        lines = [l.strip() for l in resp.splitlines() if "vless://" in l]
        # Жесткий фильтр Cloudflare сразу при чтении
        return [l for l in lines if "udp443" not in l.lower() and "cloudflare" not in l.lower()]
    except: return []

# --- ГЛАВНАЯ ЛОГИКА ---

def main():
    start_exec = time.time()
    print(f"--- ЗАПУСК СКРИПТА [{offset}] ---")
    
    cf_nets = get_net_list(CF_IPS_PATH, "https://www.cloudflare.com/ips-v4")
    hz_nets = get_net_list(HZ_IPS_PATH, HZ_SOURCE_URL)
    
    if not os.path.exists(MMDB_PATH):
        print("Загрузка GeoIP базы...")
        r = requests.get(MMDB_URL); open(MMDB_PATH, "wb").write(r.content)

    try:
        src = session.get(REMOTE_SOURCE_URL).text
        def get_var(var_name):
            pattern = rf'{var_name}\s*=\s*\[(.*?)\]'
            match = re.search(pattern, src, re.S | re.IGNORECASE)
            return re.findall(r'["\']([^"\']+)["\']', match.group(1)) if match else []
        
        extra_urls = get_var("EXTRA_URLS_FOR_26")
        std_urls = get_var("URLS")
        white_snis = get_var("SNI_DOMAINS")
        print(f"Источники: EXTRA={len(extra_urls)}, STD={len(std_urls)}, Белых SNI={len(white_snis)}")
    except Exception as e:
        print(f"Ошибка парсинга источников: {e}"); return

    g = Github(auth=Auth.Token(GITHUB_TOKEN))
    repo = g.get_repo(REPO_NAME)
    try:
        db_file = repo.get_contents(f"githubmirror/{FILENAME_OPT}")
        db = json.loads(db_file.decoded_content)
        db_sha = db_file.sha
    except:
        db = {"last_run_configs": [], "tracked": {}, "blacklist": {}}
        db_sha = None
    
    db["blacklist"] = {k: v for k, v in db.get("blacklist", {}).items() if datetime.fromisoformat(v) > now_moscow}

    final_ru, final_others = [], []
    seen_hosts, sni_counts, subnet_counts, id_counts = set(), {}, {}, {}
    new_run_keys = [] 

    with maxminddb.open_database(MMDB_PATH) as reader:
        def process_config(config, is_extra):
            nonlocal final_ru, final_others
            
            host, port, sni, cid, name = get_config_details(config)
            # 1. Базовые фильтры
            if not host or host in seen_hosts or "cloudflare" in (sni or ""): return
            if is_extra and not any(ws in sni for ws in white_snis): return
            
            with lock:
                if sni_counts.get(sni, 0) >= MAX_PER_SNI or id_counts.get(cid, 0) >= MAX_PER_ID: return

            try:
                # 2. IP фильтры
                ip = socket.gethostbyname(host)
                ip_obj = ipaddress.ip_address(ip)
                if any(ip_obj in n for n in cf_nets) or any(ip_obj in n for n in hz_nets): return
                
                subnet = ".".join(ip.split(".")[:3])
                with lock:
                    if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: return

                conf_key = config.split('#')[0]
                if conf_key in db["blacklist"]: return

                # 3. Логика Tracked / Memory
                is_ru = False
                if conf_key in db["tracked"]:
                    item = db["tracked"][conf_key]
                    if now_moscow - datetime.fromisoformat(item["added_at"]) > timedelta(days=5):
                        with lock:
                            db["blacklist"][conf_key] = (now_moscow + timedelta(days=7)).isoformat()
                            if conf_key in db["tracked"]: del db["tracked"][conf_key]
                        return
                    if not smart_ping(ip, port, sni): return
                    is_ru = item["is_ru"]
                else:
                    if not smart_ping(ip, port, sni): return
                    
                    geo = reader.get(ip)
                    ip_country = geo.get('country', {}).get('iso_code', '').upper() if geo else ""
                    name_up = name.upper()
                    is_ru_name = RU_FLAG_EMOJI in name or any(w in name_up for w in ["RU", "RUSSIA", "РОССИЯ", "RUS"])
                    
                    # Проверка провайдера
                    is_ru_api, is_bad_isp = check_isp_online(ip)
                    if is_bad_isp: return
                    
                    is_ru = is_ru_name or (ip_country == 'RU') or is_ru_api

                    # Если повторный — в tracked
                    if conf_key in db.get("last_run_configs", []):
                        with lock:
                            db["tracked"][conf_key] = {"added_at": now_moscow.isoformat(), "is_ru": is_ru}

                # 4. Распределение и Пинг
                if is_ru:
                    with lock:
                        can_add_ru = len(final_ru) < MAX_RU_CONFIGS
                    if can_add_ru:
                        p = get_triple_ping(ip, port, sni)
                        if p and MIN_RU_PING <= p <= MAX_RU_PING:
                            with lock:
                                if len(final_ru) < MAX_RU_CONFIGS:
                                    final_ru.append(config)
                                    print(f" [+] RU найден: {ip} | Ping: {p:.1f}ms | {name[:15]}")
                                    seen_hosts.add(host)
                                    new_run_keys.append(conf_key)
                                    sni_counts[sni] = sni_counts.get(sni, 0) + 1
                                    subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                                    id_counts[cid] = id_counts.get(cid, 0) + 1
                    return
                else:
                    with lock:
                        if len(final_others) < (MAX_CONFIGS - len(final_ru)):
                            final_others.append(config)
                            seen_hosts.add(host)
                            new_run_keys.append(conf_key)
                            sni_counts[sni] = sni_counts.get(sni, 0) + 1
                            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                            id_counts[cid] = id_counts.get(cid, 0) + 1
            except: pass

        def run_parallel(urls, is_extra):
            # 35 потоков на скачивание, внутри на каждый файл до 25 потоков на проверку
            with concurrent.futures.ThreadPoolExecutor(max_workers=35) as fetch_executor:
                future_to_url = {fetch_executor.submit(fetch_raw, u): u for u in urls}
                for future in concurrent.futures.as_completed(future_to_url):
                    configs = future.result()
                    if not configs: continue
                    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as process_executor:
                        [process_executor.submit(process_config, c, is_extra) for c in configs]

        run_parallel(extra_urls, True)
        run_parallel(std_urls, False)

    # 5. Сборка (2 RU, 5 Others, 3 RU, 5 Others)
    ordered, r_i, o_i, step = [], 0, 0, 0
    while (r_i < len(final_ru) or o_i < len(final_others)) and len(ordered) < MAX_CONFIGS:
        limit = RU_PATTERN[step % 4]
        if step % 2 == 0: 
            for _ in range(limit):
                if r_i < len(final_ru): ordered.append(final_ru[r_i]); r_i += 1
        else: 
            for _ in range(limit):
                if o_i < len(final_others): ordered.append(final_others[o_i]); o_i += 1
        step += 1

    # 6. Запись результатов
    db["last_run_configs"] = new_run_keys
    final_text = "\n".join(ordered)
    
    for fn in [FILENAME_VLM, FILENAME_VLM2]:
        path = f"githubmirror/{fn}"
        commit_msg = f"🚀 {offset} | RU:{len(final_ru)} Всего:{len(ordered)}"
        try:
            sha = repo.get_contents(path).sha
            repo.update_file(path, commit_msg, final_text, sha)
        except:
            repo.create_file(path, commit_msg, final_text)
    
    opt_json = json.dumps(db, indent=2)
    if db_sha:
        repo.update_file(f"githubmirror/{FILENAME_OPT}", "Sync DB", opt_json, db_sha)
    else:
        repo.create_file(f"githubmirror/{FILENAME_OPT}", "Init DB", opt_json)
        
    print(f"🏁 Время выполнения: {int(time.time()-start_exec)} сек. Найдено RU: {len(final_ru)}")

if __name__ == "__main__":
    main()
