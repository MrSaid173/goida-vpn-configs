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

MAX_CONFIGS = 300 
MAX_RU_CONFIGS = 10 
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

# --- УТИЛИТЫ ---

def is_ipv4(ip_str):
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_str))

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
        time.sleep(1.3) # Пауза для лимитов ip-api
        r = session.get(f"http://ip-api.com/json/{ip}?fields=status,countryCode,isp,org", timeout=3).json()
        if r.get("status") == "success":
            info = (r.get("isp", "") + " " + r.get("org", "")).lower()
            if any(x in info for x in ["cloudflare", "hetzner"]): return False, True
            is_ru = (r.get("countryCode") == "RU") or any(k in info for k in ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota"])
            return is_ru, False
    except: pass
    return False, False

def get_triple_ping(host, port, sni):
    latencies = []
    for _ in range(3):
        try:
            start = time.perf_counter()
            with socket.create_connection((host, port), timeout=0.5) as s:
                with ssl.create_default_context().wrap_socket(s, server_hostname=sni):
                    latencies.append((time.perf_counter() - start) * 1000)
        except: pass
        time.sleep(1.1)
    return min(latencies) if latencies else None

def smart_ping(host, port, sni):
    try:
        with socket.create_connection((host, port), timeout=1.2) as s:
            with ssl.create_default_context().wrap_socket(s, server_hostname=sni): return True
    except: return False

def get_config_details(link):
    try:
        name = requests.utils.unquote(link.split("#")[1]) if "#" in link else ""
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', link)
        id_m = re.search(r'://([^@]+)@', link)
        if h_m: return h_m.group(1), int(h_m.group(2)), (s_m.group(1).lower() if s_m else ""), (id_m.group(1) if id_m else ""), name
    except: pass
    return [None]*5

def fetch_raw_configs(url):
    try:
        resp = session.get(url, timeout=10, verify=False).text
        if "://" not in resp[:50]: resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
        return [l.strip() for l in resp.splitlines() if "vless://" in l and "udp443" not in l.lower() and "cloudflare" not in l.lower()]
    except: return []

# --- MAIN ---

def main():
    # 1. Подготовка баз
    if not os.path.exists(MMDB_PATH):
        requests.get(MMDB_URL).content # Упрощенно
    
    cf_nets = get_net_list(CF_IPS_PATH, "https://www.cloudflare.com/ips-v4")
    hz_nets = get_net_list(HZ_IPS_PATH, HZ_SOURCE_URL)
    
    g = Github(auth=Auth.Token(GITHUB_TOKEN))
    repo = g.get_repo(REPO_NAME)
    try:
        db = json.loads(repo.get_contents(f"githubmirror/{FILENAME_OPT}").decoded_content)
    except:
        db = {"last_run_configs": [], "tracked": {}, "blacklist": {}}
    
    db["blacklist"] = {k: v for k, v in db.get("blacklist", {}).items() if datetime.fromisoformat(v) > now_moscow}

    try:
        src = session.get(REMOTE_SOURCE_URL).text
        def get_l(n): return re.findall(r'["\'](https?://[^"\']+)["\']', re.search(rf'{n}\s*=\s*\[(.*?)\]', src, re.S).group(1))
        all_urls = get_l("EXTRA_URLS_FOR_26") + get_l("URLS")
    except: return

    final_ru, final_others = [], []
    current_run_keys = []
    seen_hosts, sni_counts, subnet_counts, id_counts = set(), {}, {}, {}

    # 2. Процесс сбора (Быстрый фильтр)
    with maxminddb.open_database(MMDB_PATH) as reader, concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        f_to_u = {executor.submit(fetch_raw_configs, u): u for u in all_urls}
        for future in concurrent.futures.as_completed(f_to_u):
            for config in future.result():
                if len(final_ru) >= MAX_RU_CONFIGS and len(final_others) >= (MAX_CONFIGS - MAX_RU_CONFIGS): break
                
                host, port, sni, cid, name = get_config_details(config)
                if not host or host in seen_hosts or not is_ipv4(host): continue
                
                # ЛОКАЛЬНАЯ ОТСЕЧКА (мгновенно)
                ip_obj = ipaddress.ip_address(host)
                if any(ip_obj in n for n in cf_nets) or any(ip_obj in n for n in hz_nets): continue
                
                conf_key = config.split('#')[0]
                if conf_key in db["blacklist"]: continue
                
                if sni_counts.get(sni, 0) >= MAX_PER_SNI or id_counts.get(cid, 0) >= MAX_PER_ID: continue
                subnet = ".".join(host.split(".")[:3])
                if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue

                try:
                    is_ru = False
                    # Если уже трекаем - используем старые данные (экономим API)
                    if conf_key in db["tracked"]:
                        item = db["tracked"][conf_key]
                        if now_moscow - datetime.fromisoformat(item["added_at"]) > timedelta(days=5):
                            db["blacklist"][conf_key] = (now_moscow + timedelta(days=7)).isoformat()
                            del db["tracked"][conf_key]; continue
                        if not smart_ping(host, port, sni): continue
                        is_ru = item["is_ru"]
                    else:
                        # Новый IP: проверяем MaxMind сначала (локально)
                        geo = reader.get(host)
                        ip_country = geo.get('country', {}).get('iso_code', '').upper() if geo else ""
                        is_ru_name = RU_FLAG_EMOJI in name or "RUSS" in name.upper()
                        is_ru_candidate = is_ru_name or (ip_country == 'RU')
                        
                        # API только если это потенциальный RU или мы не уверены
                        is_ru_api, is_bad_isp = check_isp_api(host)
                        if is_bad_isp or not smart_ping(host, port, sni): continue
                        is_ru = is_ru_candidate or is_ru_api
                        
                        if conf_key in db["last_run_configs"]:
                            db["tracked"][conf_key] = {"added_at": now_moscow.isoformat(), "is_ru": is_ru}

                    if is_ru:
                        if len(final_ru) < MAX_RU_CONFIGS:
                            p = get_triple_ping(host, port, sni)
                            if p and MIN_RU_PING <= p <= MAX_RU_PING: final_ru.append(config)
                            else: continue
                        else: continue # RU больше не нужны
                    else:
                        if len(final_others) < (MAX_CONFIGS - len(final_ru)): final_others.append(config)
                        else: continue

                    seen_hosts.add(host)
                    current_run_keys.append(conf_key)
                    subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                    sni_counts[sni] = sni_counts.get(sni, 0) + 1
                    id_counts[cid] = id_counts.get(cid, 0) + 1
                except: continue

    # 3. Сборка очереди
    ordered = []
    r_i, o_i, step = 0, 0, 0
    while (r_i < len(final_ru) or o_i < len(final_others)) and len(ordered) < MAX_CONFIGS:
        limit = RU_PATTERN[step % 4]
        if step % 2 == 0:
            for _ in range(limit):
                if r_i < len(final_ru): ordered.append(final_ru[r_i]); r_i += 1
        else:
            for _ in range(limit):
                if o_i < len(final_others): ordered.append(final_others[o_i]); o_i += 1
        step += 1

    # 4. Сохранение
    db["last_run_configs"] = current_run_keys
    output = "\n".join(ordered)
    for fn in [FILENAME_VLM, FILENAME_VLM2]:
        path = f"githubmirror/{fn}"
        try:
            sha = repo.get_contents(path).sha
            repo.update_file(path, f"🚀 {offset}", output, sha)
        except: repo.create_file(path, f"🚀 {offset}", output)
    
    repo.update_file(f"githubmirror/{FILENAME_OPT}", "Sync", json.dumps(db, indent=2), repo.get_contents(f"githubmirror/{FILENAME_OPT}").sha)

if __name__ == "__main__":
    main()
