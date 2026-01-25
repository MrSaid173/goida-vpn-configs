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
FILENAME_OPT = "opt.json"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
MMDB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
HZ_SOURCE_URL = "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/24940/ipv4-aggregated.txt"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MMDB_PATH = os.path.join(BASE_DIR, "GeoLite2-Country.mmdb")
CF_IPS_PATH = os.path.join(BASE_DIR, "cloudflare_ips.txt")
HZ_IPS_PATH = os.path.join(BASE_DIR, "hetzner_ips.txt")

MAX_CONFIGS = 100 
MAX_RU_CONFIGS = 5 
MAX_PER_SUBNET = 3 
MAX_PER_SNI = 15
MAX_PER_ID = 3
MIN_RU_PING = 110.0
MAX_RU_PING = 500.0

RU_PATTERN = [2, 5, 3, 5] 

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
now_moscow = datetime.now(zone)
offset = now_moscow.strftime("%H:%M | %d.%m.%Y")

RU_FLAG_EMOJI = "🇷🇺"
# Словарь для точной идентификации стран и исключения ошибок
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
}

# --- УТИЛИТЫ ---

def get_net_list(path, url):
    if os.path.exists(path) and (datetime.now() - datetime.fromtimestamp(os.path.getmtime(path)) < timedelta(days=3)):
        with open(path, "r") as f: return [ipaddress.ip_network(l.strip()) for l in f if "/" in l]
    try:
        r = session.get(url, timeout=10)
        with open(path, "w") as f: f.write(r.text)
        return [ipaddress.ip_network(l.strip()) for l in r.text.splitlines() if "/" in l]
    except: return []

def check_isp_api(ip):
    try:
        time.sleep(1.3)
        r = session.get(f"http://ip-api.com/json/{ip}?fields=status,countryCode,isp,org", timeout=3).json()
        if r.get("status") == "success":
            info = (r.get("isp", "") + " " + r.get("org", "")).lower()
            if any(x in info for x in ["cloudflare", "hetzner"]): return False, True
            is_ru = (r.get("countryCode") == "RU") or any(k in info for k in ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota"])
            return is_ru, False
    except: pass
    return False, False

def smart_ping(host, port, sni):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=1.2) as s:
            with ctx.wrap_socket(s, server_hostname=sni): return True
    except: return False

def get_triple_ping(host, port, sni):
    lats = []
    for _ in range(3):
        start = time.perf_counter()
        if smart_ping(host, port, sni): lats.append((time.perf_counter() - start) * 1000)
        time.sleep(1.1)
    return min(lats) if lats else None

def get_config_details(link):
    try:
        name = requests.utils.unquote(link.split("#")[1]) if "#" in link else ""
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', link)
        id_m = re.search(r'://([^@]+)@', link)
        if h_m: return h_m.group(1), int(h_m.group(2)), (s_m.group(1).lower() if s_m else ""), (id_m.group(1) if id_m else ""), name
    except: pass
    return [None]*5

def fetch_raw(url):
    try:
        resp = session.get(url, timeout=10).text
        if "://" not in resp[:50]: resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
        return [l.strip() for l in resp.splitlines() if "vless://" in l and "udp443" not in l.lower()]
    except: return []

# --- ГЛАВНЫЙ ПРОЦЕСС ---

def main():
    if not os.path.exists(MMDB_PATH):
        try:
            r = requests.get(MMDB_URL, timeout=30)
            with open(MMDB_PATH, "wb") as f: f.write(r.content)
        except: pass

    cf_nets = get_net_list(CF_IPS_PATH, "https://www.cloudflare.com/ips-v4")
    hz_nets = get_net_list(HZ_IPS_PATH, HZ_SOURCE_URL)
    
    try:
        src = session.get(REMOTE_SOURCE_URL).text
        def get_l(n): return re.findall(r'["\']([^"\']+)["\']', re.search(rf'{n}\s*=\s*\[(.*?)\]', src, re.S).group(1))
        white_snis = get_l("SNI_DOMAINS")
        extra_urls = get_l("EXTRA_URLS_FOR_26")
        std_urls = get_l("URLS")
    except: return

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
    current_keys = []

    with maxminddb.open_database(MMDB_PATH) as reader:
        def process_source(urls, is_extra):
            for url in urls:
                for config in fetch_raw(url):
                    if len(final_ru) + len(final_others) >= MAX_CONFIGS: return
                    
                    host, port, sni, cid, name = get_config_details(config)
                    if not host or host in seen_hosts: continue
                    
                    if is_extra and not any(ws in sni for ws in white_snis): continue
                    
                    try:
                        ip_obj = ipaddress.ip_address(host)
                        if any(ip_obj in n for n in cf_nets) or any(ip_obj in n for n in hz_nets): continue
                    except: continue

                    conf_key = config.split('#')[0]
                    if conf_key in db["blacklist"]: continue
                    if sni_counts.get(sni, 0) >= MAX_PER_SNI or id_counts.get(cid, 0) >= MAX_PER_ID: continue
                    
                    subnet = ".".join(host.split(".")[:3])
                    if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue

                    try:
                        is_ru = False
                        if conf_key in db["tracked"]:
                            item = db["tracked"][conf_key]
                            if now_moscow - datetime.fromisoformat(item["added_at"]) > timedelta(days=5):
                                db["blacklist"][conf_key] = (now_moscow + timedelta(days=7)).isoformat()
                                del db["tracked"][conf_key]; continue
                            if not smart_ping(host, port, sni): continue
                            is_ru = item["is_ru"]
                        else:
                            geo = reader.get(host)
                            ip_country = geo.get('country', {}).get('iso_code', '').upper() if geo else ""
                            name_up = name.upper()
                            
                            # ЛОГИКА ОПРЕДЕЛЕНИЯ RU С ИСПОЛЬЗОВАНИЕМ ФЛАГОВ
                            is_ru_by_name = RU_FLAG_EMOJI in name or any(word in name_up for word in COUNTRY_MAP["RU"])
                            is_ru_final = is_ru_by_name or (ip_country == 'RU')

                            # Проверка на ложные страны (если в имени US, а IP из RU)
                            found_other = False
                            for code, aliases in COUNTRY_MAP.items():
                                if code == "RU": continue
                                if any(a in name_up for a in aliases):
                                    found_other = True
                                    if ip_country and ip_country != code: break
                            
                            if found_other and not is_ru_by_name: continue

                            is_ru_api, is_bad = check_isp_api(host)
                            if is_bad or not smart_ping(host, port, sni): continue
                            is_ru = is_ru_final or is_ru_api
                            
                            if conf_key in db["last_run_configs"]:
                                db["tracked"][conf_key] = {"added_at": now_moscow.isoformat(), "is_ru": is_ru}

                        if is_ru:
                            if len(final_ru) < MAX_RU_CONFIGS:
                                p = get_triple_ping(host, port, sni)
                                if p and MIN_RU_PING <= p <= MAX_RU_PING: final_ru.append(config)
                                else: continue
                            else: continue
                        else:
                            final_others.append(config)

                        seen_hosts.add(host)
                        current_keys.append(conf_key)
                        sni_counts[sni] = sni_counts.get(sni, 0) + 1
                        subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                        id_counts[cid] = id_counts.get(cid, 0) + 1
                    except: continue

        process_source(extra_urls, True)
        process_source(std_urls, False)

    # Паттерн 2-5-3-5
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

    db["last_run_configs"] = current_keys
    out_text = "\n".join(ordered)
    for fn in [FILENAME_VLM, FILENAME_VLM2]:
        path = f"githubmirror/{fn}"
        try:
            sha = repo.get_contents(path).sha
            repo.update_file(path, f"🚀 {offset} | RU: {len(final_ru)}", out_text, sha)
        except: repo.create_file(path, f"🚀 {offset}", out_text)
    
    if db_sha:
        repo.update_file(f"githubmirror/{FILENAME_OPT}", "Sync DB", json.dumps(db, indent=2), db_sha)
    else:
        repo.create_file(f"githubmirror/{FILENAME_OPT}", "Init DB", json.dumps(db, indent=2))

if __name__ == "__main__":
    main()
