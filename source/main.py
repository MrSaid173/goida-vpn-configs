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

EXCLUDED_SNI_DOMAINS = ["vk"]
BAD_HOSTING_KEYWORDS = ["cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google", "microsoft", "ovh", "linode", "servers", "work", "oracle", "leaseweb", "m247", "akamai", "host"]

MAX_JITTER = 50  
MAX_CONFIGS = 50 
MAX_RU_CONFIGS = 5
MAX_PER_COUNTRY = 15 
MAX_PER_SUBNET = 2 
MAX_PER_SNI = 15
MAX_PER_ID = 6
MAX_FAILED_PER_SUBNET = 4 

MIN_RU_PING, MAX_RU_PING = 90.0, 370.0
MIN_WORLD_PING, MAX_WORLD_PING = 25.0, 400.0

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
session.headers.update({'Connection': 'keep-alive'})

zone = zoneinfo.ZoneInfo("Europe/Moscow")
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")

COUNTRY_MAP = {
    "RU": {"aliases": ["RUSSIA", "РОССИЯ", "RUS", "🇷🇺"], "full": "Russia", "flag": "🇷🇺"},
    "US": {"aliases": ["USA", "UNITED STATES", "AMERICA", "🇺🇸"], "full": "USA", "flag": "🇺🇸"},
    "DE": {"aliases": ["GERMANY", "ГЕРМАНИЯ", "DEUTSCHLAND", "🇩🇪"], "full": "Germany", "flag": "🇩🇪"},
    "NL": {"aliases": ["NETHERLANDS", "НИДЕРЛАНДЫ", "HOLLAND", "🇳🇱"], "full": "The Netherlands", "flag": "🇳🇱"},
    "GB": {"aliases": ["UNITED KINGDOM", "ENGLAND", "🇬🇧"], "full": "United Kingdom", "flag": "🇬🇧"},
    "TR": {"aliases": ["TURKEY", "ТУРЦИЯ", "TURKIYE", "ТҮРКИЕ", "TÜRKIYE", "🇹🇷"], "full": "Turkey", "flag": "🇹🇷"},
    "KZ": {"aliases": ["KAZAKHSTAN", "КАЗАХСТАН", "🇰🇿"], "full": "Kazakhstan", "flag": "🇰🇿"},
    "FI": {"aliases": ["FINLAND", "ФИНЛЯНДИЯ", "🇫🇮"], "full": "Finland", "flag": "🇫🇮"},
    "PL": {"aliases": ["POLAND", "ПОЛЬША", "🇵🇱"], "full": "Poland", "flag": "🇵🇱"},
    "AT": {"aliases": ["AUSTRIA", "АВСТРИЯ", "🇦🇹"], "full": "Austria", "flag": "🇦🇹"},
    "LV": {"aliases": ["LATVIA", "ЛАТВИЯ", "🇱🇻"], "full": "Latvia", "flag": "🇱🇻"},
    "NO": {"aliases": ["NORWAY", "НОРВЕГИЯ", "🇳🇴"], "full": "Norway", "flag": "🇳🇴"},
    "SE": {"aliases": ["SWEDEN", "ШВЕЦИЯ", "🇸🇪"], "full": "Sweden", "flag": "🇸🇪"},
    "UA": {"aliases": ["UKRAINE", "УКРАИНА", "🇺🇦"], "full": "Ukraine", "flag": "🇺🇦"},
    "CA": {"aliases": ["CANADA", "КАНАДА", "🇨🇦"], "full": "Canada", "flag": "🇨🇦"},
    "CH": {"aliases": ["SWITZERLAND", "ШВЕЙЦАРИЯ", "🇨🇭"], "full": "Switzerland", "flag": "🇨🇭"},
    "CZ": {"aliases": ["CZECHIA", "CZECH REPUBLIC", "ЧЕХИЯ", "🇨🇿"], "full": "Czechia", "flag": "🇨🇿"},
    "IT": {"aliases": ["ITALY", "ИТАЛИЯ", "🇮🇹"], "full": "Italy", "flag": "🇮🇹"},
    "EE": {"aliases": ["ESTONIA", "ЭСТОНИЯ", "🇪🇪"], "full": "Estonia", "flag": "🇪🇪"},
    "FR": {"aliases": ["FRANCE", "ФРАНЦИЯ", "🇫🇷"], "full": "France", "flag": "🇫🇷"},
    "SG": {"aliases": ["SINGAPORE", "СИНГАПУР", "🇸🇬"], "full": "Singapore", "flag": "🇸🇬"},
    "BG": {"aliases": ["BULGARIA", "БОЛГАРИЯ", "🇧🇬"], "full": "Bulgaria", "flag": "🇧🇬"},
    "LT": {"aliases": ["LITHUANIA", "ЛИТВА", "🇱ТУА", "🇱🇹"], "full": "Lithuania", "flag": "🇱🇹"},
    "BR": {"aliases": ["BRAZIL", "БРАЗИЛИЯ", "🇧🇷"], "full": "Brazil", "flag": "🇧🇷"},
    "JP": {"aliases": ["JAPAN", "ЯПОНИЯ", "🇯🇵"], "full": "Japan", "flag": "🇯🇵"},
    "IE": {"aliases": ["IRELAND", "ИРЛАНДИЯ", "🇮🇪"], "full": "Ireland", "flag": "🇮🇪"},
    "HK": {"aliases": ["HONG KONG", "ГОНКОНГ", "🇭🇰"], "full": "Hong Kong", "flag": "🇭🇰"},
    "IS": {"aliases": ["ICELAND", "ИСЛАНДИЯ", "🇮🇸"], "full": "Iceland", "flag": "🇮🇸"},
    "AL": {"aliases": ["ALBANIA", "АЛБАНИЯ", "🇦🇱"], "full": "Albania", "flag": "🇦🇱"},
    "CO": {"aliases": ["COLOMBIANA", "КОЛУМБИЯ", "🇨🇴"], "full": "Colombiana", "flag": "🇨🇴"},
    "MD": {"aliases": ["MOLDOVA", "МОЛДОВА", "🇲🇩"], "full": "Moldova", "flag": "🇲🇩"},
    "HU": {"aliases": ["HUNGARY", "ВЕНГРИЯ", "🇭🇺"], "full": "Hungary", "flag": "🇭🇺"},
    "ES": {"aliases": ["SPAIN", "ИСПАНИЯ", "🇪🇸"], "full": "Spain", "flag": "🇪🇸"},
    "IR": {"aliases": ["IRAN", "ИРАН", "🇮🇷"], "full": "Iran", "flag": "🇮🇷"},
}

lock = threading.Lock()
api_semaphore = threading.Semaphore(3)
ip_cache = {}
failed_subnets = {} 
last_api_call = 0

def is_valid_ipv4(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except: return False

def rename_config(link, country_code, index, is_hosting=False, is_white_sni=False):
    base_part = link.split('#')[0].rstrip('/')
    country_info = COUNTRY_MAP.get(country_code, {"full": country_code, "flag": "🌐"})
    tags = []
    if is_hosting is True: tags.append("HOST")
    if is_white_sni: tags.append("SNI-RU")
    tag_str = f" [{'|'.join(tags)}]" if tags else ""
    new_name = f"{country_info['flag']} {country_info['full']} — #{index}{tag_str}"
    return f"{base_part}#{requests.utils.quote(new_name)}"

def apply_clean_params(config_link):
    parts = config_link.split("#", 1)
    base = parts[0]
    base = re.sub(r'[&?]fp=[^&?#]+', '', base)
    sep = "&" if "?" in base else "?"
    base = f"{base}{sep}fp=random"
    base = base.replace("/?", "?").replace("/&", "&").replace("//", "/").replace(":/", "://")
    return f"{base}#{parts[1]}" if len(parts) > 1 else base

def check_isp_info(ip_str):
    global last_api_call
    with lock:
        if ip_str in ip_cache: return ip_cache[ip_str]
    
    with api_semaphore:
        try:
            with lock:
                elapsed = time.perf_counter() - last_api_call
                if elapsed < 1.2: time.sleep(1.2 - elapsed)
                last_api_call = time.perf_counter()
            r = session.get(f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,isp,org,as,asname,hosting", timeout=5).json()
            if r.get("status") == "success":
                full_info = f"{r.get('isp')} {r.get('org')} {r.get('as')} {r.get('asname')}".lower()
                is_banned = any(word in full_info for word in BAD_HOSTING_KEYWORDS)
                res = (r.get("countryCode"), full_info, "BANNED" if is_banned else r.get("hosting", False))
                with lock: ip_cache[ip_str] = res
                return res
        except: pass
        return None, None, False

def fast_ping(host, port, sni):
    try:
        context = ssl.create_default_context()
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=0.8) as sock:
            with context.wrap_socket(sock, server_hostname=sni):
                return int((time.perf_counter() - start) * 1000)
    except: return None

def full_ping_analysis(host, port, sni, initial_ping):
    pings = [initial_ping]
    try:
        context = ssl.create_default_context()
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        for _ in range(2):
            start = time.perf_counter()
            with socket.create_connection((host, port), timeout=1.0) as sock:
                with context.wrap_socket(sock, server_hostname=sni):
                    pings.append(int((time.perf_counter() - start) * 1000))
        avg = sum(pings) // len(pings)
        jit = sum(abs(p - avg) for p in pings) // len(pings)
        return avg, jit
    except: return None

def get_config_details(link):
    try:
        name = requests.utils.unquote(link.split("#")[1]) if "#" in link else ""
        clean_link = re.sub(r'[^\x20-\x7E]', '', link).strip()
        cid_match = re.search(r'://([^@]+)@', clean_link)
        cid = cid_match.group(1) if cid_match else ""
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', clean_link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', clean_link)
        sni = s_m.group(1).lower() if s_m else ""
        if h_m and is_valid_ipv4(h_m.group(1)):
            return h_m.group(1), int(h_m.group(2)), sni, cid, name
    except: pass
    return None, None, None, None, None

def fetch_raw_configs(url):
    try:
        resp = session.get(url, timeout=7, verify=False).text
        if "://" not in resp[:50]:
            try: resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
            except: pass
        return [l.strip() for l in re.findall(r'(?:vless|ssr|tuic|hysteria|hysteria2)://[^\s]+', resp) if not l.startswith(("ss://", "trojan://"))]
    except: return []

def main():
    start_total = time.perf_counter()
    print(f"--- 🟢 ЗАПУСК [{offset}] ---", flush=True)
    
    src_text = session.get(REMOTE_SOURCE_URL).text
    def get_list(var):
        m = re.search(rf'{var}\s*=\s*\[(.*?)\]', src_text, re.S | re.I)
        return re.findall(r'["\']([^"\']+)["\']', m.group(1)) if m else []
        
    extra_urls, std_urls = get_list("EXTRA_URLS_FOR_26"), get_list("URLS")
    sni_domains = set(s.lower() for s in get_list("SNI_DOMAINS"))

    vlm2_results = []
    vlm_results = []
    seen_ips, subnet_counts, id_counts, country_counts = set(), {}, {}, {}
    ru_count = 0

    def validate(config, is_priority, is_white):
        nonlocal ru_count
        # Проверяем лимиты без запаса
        if len(vlm_results) >= MAX_CONFIGS and len(vlm2_results) >= MAX_CONFIGS: return

        # Фильтр на наличие заполненного параметра host=
        if re.search(r'[?&]host=[^&#\s]+', config.lower()): return

        host, port, sni, cid, name = get_config_details(config)
        if not host: return
        
        with lock:
            if host in seen_ips: return

        if any(exc in sni for exc in EXCLUDED_SNI_DOMAINS): return
        if not sni or (sni in sni_domains) != is_white: return
        
        subnet = ".".join(host.split(".")[:3])
        with lock:
            if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET or id_counts.get(cid, 0) >= MAX_PER_ID: return
            if failed_subnets.get(subnet, 0) >= MAX_FAILED_PER_SUBNET: return

        p1 = fast_ping(host, port, sni)
        if not p1 or p1 > MAX_WORLD_PING:
            with lock: failed_subnets[subnet] = failed_subnets.get(subnet, 0) + 1
            return

        ip_cc, ip_isp, ip_h_stat = check_isp_info(host)
        if not ip_cc or ip_h_stat == "BANNED": return
        if ip_h_stat is True and p1 > 200: return

        is_ru = (ip_cc == "RU")
        is_name_ru = any(a in name.upper() for a in COUNTRY_MAP["RU"]["aliases"])
        if is_ru != is_name_ru: return

        with lock:
            if is_ru and ru_count >= MAX_RU_CONFIGS: return
            if not is_ru and country_counts.get(ip_cc, 0) >= MAX_PER_COUNTRY: return
            if host in seen_ips: return 
            seen_ips.add(host)

        full = full_ping_analysis(host, port, sni, p1)
        if not full or full[1] > MAX_JITTER: return
        
        with lock:
            is_xhttp = "xhttp" in config.lower()
            res_entry = {
                "link": apply_clean_params(config), 
                "ping": full[0], 
                "country": ip_cc, 
                "is_priority": is_priority, 
                "white_sni": is_white, 
                "is_hosting": ip_h_stat
            }
            
            # Добавляем в vlm2, если список еще не полон
            if len(vlm2_results) < MAX_CONFIGS:
                vlm2_results.append(res_entry)
            
            # Добавляем в vlm, если это не xhttp и список не полон
            if not is_xhttp and len(vlm_results) < MAX_CONFIGS:
                vlm_results.append(res_entry)
            
            if is_ru: ru_count += 1
            else: country_counts[ip_cc] = country_counts.get(ip_cc, 0) + 1
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
            id_counts[cid] = id_counts.get(cid, 0) + 1
            
            print(f"[FOUND] {ip_cc} | {full[0]}ms | {host} {'(xHTTP)' if is_xhttp else ''}", flush=True)

    # Сбор
    raw_extra, raw_std = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as g:
        f_extra = [g.submit(fetch_raw_configs, u) for u in set(extra_urls)]
        f_std = [g.submit(fetch_raw_configs, u) for u in set(std_urls)]
        for f in f_extra: raw_extra.extend(f.result())
        for f in f_std: raw_std.extend(f.result())

    print(f"--- Собрано: Extra={len(raw_extra)}, Std={len(raw_std)} ---")

    groups = [(raw_extra, True, True), (raw_std, False, True), (raw_extra, True, False), (raw_std, False, False)]
    for group, priority, is_white in groups:
        if len(vlm_results) >= MAX_CONFIGS and len(vlm2_results) >= MAX_CONFIGS: break
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as v:
            for c in set(group): v.submit(validate, c, priority, is_white)

    def finalize_list(results, is_vlm1=False):
        results.sort(key=lambda x: (-(2 if (x['is_priority'] and x['white_sni']) else (1 if x['white_sni'] else 0)), x['ping']))
        output = []
        for i, r in enumerate(results[:MAX_CONFIGS], 1):
            link = rename_config(r['link'], r['country'], i, r['is_hosting'], r['white_sni'])
            if is_vlm1: link = link.replace("-udp443", "")
            output.append(link)
        return output

    f_v1, f_v2 = finalize_list(vlm_results, True), finalize_list(vlm2_results)

    try:
        repo = Github(auth=Auth.Token(GITHUB_TOKEN)).get_repo(REPO_NAME)
        for fn, lst in [(FILENAME_VLM, f_v1), (FILENAME_VLM2, f_v2)]:
            path, content = f"githubmirror/{fn}", "\n".join(lst)
            msg = f"🚀 {fn} | T: {len(lst)} | {offset}"
            try:
                sha = repo.get_contents(path).sha
                repo.update_file(path, msg, content, sha)
            except: repo.create_file(path, msg, content)
        print(f"--- Обновлено успешно [vlm: {len(f_v1)}, vlm2: {len(f_v2)}] ---")
    except Exception as e: print(f"GH Error: {e}")
    print(f"--- 🏁 ГОТОВО за {time.perf_counter() - start_total:.1f}с ---")

if __name__ == "__main__":
    main()
    
