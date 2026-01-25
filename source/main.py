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
MAX_RU_CONFIGS = 2  
MAX_PER_SUBNET = 3 
MAX_PER_SNI = 15
MAX_PER_ID = 3
MIN_RU_PING = 110.0
MAX_RU_PING = 450.0

RU_PATTERN = [2, 5, 3, 5] 

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
start_time = datetime.now(zone)
offset = start_time.strftime("%H:%M | %d.%m.%Y")

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

def get_net_list(path, url):
    if os.path.exists(path) and (datetime.now() - datetime.fromtimestamp(os.path.getmtime(path)) < timedelta(days=3)):
        with open(path, "r") as f: return [ipaddress.ip_network(l.strip()) for l in f if "/" in l]
    try:
        r = requests.get(url, timeout=10)
        with open(path, "w") as f: f.write(r.text)
        return [ipaddress.ip_network(l.strip()) for l in r.text.splitlines() if "/" in l]
    except: return []

def smart_ping(host, port, sni):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=1.1) as s:
            start = time.perf_counter()
            with ctx.wrap_socket(s, server_hostname=sni):
                return (time.perf_counter() - start) * 1000
    except: return None

def check_isp_online(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,countryCode,isp,org", timeout=4).json()
        if r.get("status") == "success":
            info = (str(r.get("isp", "")) + " " + str(r.get("org", ""))).lower()
            if any(x in info for x in ["cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google"]):
                return False, True
            is_ru = (r.get("countryCode") == "RU") or any(k in info for k in ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota"])
            return is_ru, False
    except: pass
    return False, False

def get_config_details(link):
    try:
        name = requests.utils.unquote(link.split("#")[1]) if "#" in link else ""
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', link)
        id_m = re.search(r'://([^@]+)@', link)
        if h_m: return h_m.group(1), int(h_m.group(2)), (s_m.group(1).lower() if s_m else ""), (id_m.group(1) if id_m else ""), name
    except: pass
    return None, None, None, None, None

def fetch_raw_configs(url):
    try:
        resp = session.get(url, timeout=12, verify=False).text
        if "://" not in resp[:50]:
            try: resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
            except: pass
        lines = [l.strip() for l in resp.splitlines() if "vless://" in l]
        return [l for l in lines if "cloudflare" not in l.lower()]
    except: return []

# --- MAIN ---

def main():
    if not os.path.exists(MMDB_PATH):
        r = requests.get(MMDB_URL); open(MMDB_PATH, "wb").write(r.content)

    cf_nets = get_net_list(CF_IPS_PATH, "https://www.cloudflare.com/ips-v4")
    hz_nets = get_net_list(HZ_IPS_PATH, HZ_SOURCE_URL)
    
    try:
        src = session.get(REMOTE_SOURCE_URL).text
        def get_var(v):
            m = re.search(rf'{v}\s*=\s*\[(.*?)\]', src, re.S | re.IGNORECASE)
            return re.findall(r'["\']([^"\']+)["\']', m.group(1)) if m else []
        extra_urls, std_urls, sni_domains = get_var("EXTRA_URLS_FOR_26"), get_var("URLS"), get_var("SNI_DOMAINS")
    except: return

    g = Github(auth=Auth.Token(GITHUB_TOKEN))
    repo = g.get_repo(REPO_NAME)
    try:
        db_f = repo.get_contents(f"githubmirror/{FILENAME_OPT}")
        db = json.loads(db_f.decoded_content); db_sha = db_f.sha
    except: db = {"last_run_configs": [], "tracked": {}, "blacklist": {}}; db_sha = None

    db["blacklist"] = {k: v for k, v in db.get("blacklist", {}).items() if datetime.fromisoformat(v) > datetime.now(zone)}
    
    final_ru, final_others = [], []
    seen_hosts, sni_counts, subnet_counts, id_counts = set(), {}, {}, {}
    current_run_keys = []

    with maxminddb.open_database(MMDB_PATH) as reader:
        def process_url(url, use_sni_filter):
            configs = fetch_raw_configs(url)
            for config in configs:
                host, port, sni, cid, name = get_config_details(config)
                if not host or host in seen_hosts or "cloudflare" in (sni or ""): continue
                if use_sni_filter and not any(d in (sni or "") for d in sni_domains): continue
                
                with lock:
                    if sni_counts.get(sni, 0) >= MAX_PER_SNI or id_counts.get(cid, 0) >= MAX_PER_ID: continue

                try:
                    ip = socket.gethostbyname(host)
                    ip_obj = ipaddress.ip_address(ip)
                    if any(ip_obj in n for n in cf_nets) or any(ip_obj in n for n in hz_nets): continue

                    subnet = ".".join(ip.split(".")[:3])
                    with lock:
                        if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue

                    conf_key = config.split('#')[0]
                    if conf_key in db["blacklist"]: continue

                    is_ru = False
                    if conf_key in db["tracked"]:
                        item = db["tracked"][conf_key]
                        if datetime.now(zone) - datetime.fromisoformat(item["added_at"]) > timedelta(days=5):
                            with lock: db["blacklist"][conf_key] = (datetime.now(zone) + timedelta(days=7)).isoformat()
                            continue
                        ping_val = smart_ping(ip, port, sni)
                        if ping_val is None: continue
                        is_ru = item["is_ru"]
                    else:
                        ping_val = smart_ping(ip, port, sni)
                        if ping_val is None: continue
                        
                        geo = reader.get(ip)
                        ip_country = geo.get('country', {}).get('iso_code', '').upper() if geo else ""
                        name_up = name.upper()
                        is_ru_name = RU_FLAG_EMOJI in name or any(w in name_up for w in ["RU", "RUSSIA", "РОССИЯ"])
                        
                        is_ru_api, is_bad = check_isp_online(ip)
                        if is_bad: continue
                        is_ru = is_ru_name or (ip_country == 'RU') or is_ru_api

                        if conf_key in db.get("last_run_configs", []):
                            with lock: db["tracked"][conf_key] = {"added_at": datetime.now(zone).isoformat(), "is_ru": is_ru}

                    with lock:
                        if is_ru:
                            if len(final_ru) < MAX_RU_CONFIGS and MIN_RU_PING <= ping_val <= MAX_RU_PING:
                                final_ru.append(config)
                                print(f" [+] RU: {ip} | Ping: {ping_val:.1f}ms | {name[:15]}")
                            else: continue
                        else:
                            if len(final_others) < (MAX_CONFIGS - len(final_ru)):
                                final_others.append(config)
                            else: continue
                        
                        seen_hosts.add(host)
                        current_run_keys.append(conf_key)
                        sni_counts[sni] = sni_counts.get(sni, 0) + 1
                        subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                        id_counts[cid] = id_counts.get(cid, 0) + 1
                except: continue

        def run_stage(urls, sni_filt, label):
            print(f"--- [ЭТАП: {label}] ---")
            with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
                [executor.submit(process_url, u, sni_filt) for u in urls]

        run_stage(extra_urls, True, "EXTRA")
        run_stage(std_urls, True, "STD")
        if len(final_others) < 100: run_stage(extra_urls + std_urls, False, "RESERVE")

    # Паттерн 2-5-3-5
    ordered, r_i, o_i, step = [], 0, 0, 0
    while (r_i < len(final_ru) or o_i < len(final_others)) and len(ordered) < MAX_CONFIGS:
        limit = RU_PATTERN[step % 4]
        for _ in range(limit):
            if step % 2 == 0:
                if r_i < len(final_ru): ordered.append(final_ru[r_i]); r_i += 1
            else:
                if o_i < len(final_others): ordered.append(final_others[o_i]); o_i += 1
        step += 1

    db["last_run_configs"] = current_run_keys
    for fn, lst in [(FILENAME_VLM, ordered), (FILENAME_VLM2, ordered)]:
        path = f"githubmirror/{fn}"
        try:
            sha = repo.get_contents(path).sha
            repo.update_file(path, f"🚀 {offset} | RU:{len(final_ru)}", "\n".join(lst), sha)
        except: repo.create_file(path, f"🚀 {offset}", "\n".join(lst))
    
    repo.update_file(f"githubmirror/{FILENAME_OPT}", "Sync", json.dumps(db, indent=2), db_sha)
    print(f"🏁 RU: {len(final_ru)} | Время: {str(datetime.now(zone)-start_time).split('.')[0]}")

if __name__ == "__main__":
    main()
