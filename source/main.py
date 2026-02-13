import os, re, requests, urllib3, concurrent.futures, ipaddress, base64, json, time, socket, ssl, random
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
SECONDARY_WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt"

# --- ЛИМИТЫ ---
MIN_XHTTP = 5   
MAX_XHTTP = 5   
MIN_RU_CONFIGS = 5  
MAX_RU_CONFIGS = 5  

INTERLEAVE_STEP = 3 
EXCLUDED_SNI_DOMAINS = ["userapi"]
BAD_HOSTING_KEYWORDS = ["cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google", "microsoft", "ovh", "linode", "servers", "work", "oracle", "leaseweb", "m247", "akamai", "host"]

BANNED_ASNAME_PATTERNS = [
    "-ru", "-ua", "-by", "-kz", "-uz", "-ge", "-am", "-az", "-md", "-tj", "-kg", "-tm",
    "-us", "-ca", "-mx", "-br", "-ar", "-cl", "-co", "-pe", "-ve",
    "-de", "-nl", "-gb", "-uk", "-fr", "-it", "-es", "-pl", "-at", "-ch", "-se", "-no",
    "-fi", "-dk", "-ie", "-pt", "-be", "-cz", "-hu", "-ro", "-bg", "-gr", "-tr", "-ee",
    "-lv", "-lt", "-si", "-sk", "-hr", "-rs", "-me", "-ba", "-al", "-is", "-lu", "-mt",
    "-cn", "-hk", "-sg", "-jp", "-kr", "-in", "-tw", "-vn", "-th", "-my", "-ph", "-id",
    "-ae", "-il", "-sa", "-ir", "-iq", "-jo", "-kw", "-qa", "-om", "-ye",
    "-au", "-nz", "-za", "-ng", "-eg", "-ke", "-ma", "-dz", "-tn"
]

MAX_JITTER = 50
MAX_JITTER_RATIO = 0.4 

MAX_CONFIGS = 50 
MAX_TOTAL_SNI_RU = MAX_CONFIGS // 2
MAX_TOP_RU_SNI = 5
MAX_PER_COUNTRY = 15 
MAX_PER_SUBNET = 3 
MAX_PER_ID = 6
MAX_FAILED_PER_SUBNET = 4
MAX_SAME_SNI_RU = 2      
MAX_SAME_SNI_WORLD = 15  

MIN_RU_PING, MAX_RU_PING = 90.0, 400.0
MIN_WORLD_PING, MAX_WORLD_PING = 25.0, 500.0
MAX_RU_PING_XHTTP = MAX_RU_PING + 150
MAX_WORLD_PING_XHTTP = MAX_WORLD_PING + 150

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
    "LT": {"aliases": ["LITHUANIA", "ЛИТВА", "🇱🇹"], "full": "Lithuania", "flag": "🇱🇹"},
    "BR": {"aliases": ["BRAZIL", "БРАЗИЛИЯ", "🇧🇷"], "full": "Brazil", "flag": "🇧🇷"},
    "JP": {"aliases": ["JAPAN", "ЯПОНИЯ", "🇯🇵"], "full": "Japan", "flag": "🇯🇵"},
    "IE": {"aliases": ["IRELAND", "ИРЛАНДИЯ", "🇮🇪"], "full": "Ireland", "flag": "🇮🇪"},
    "HK": {"aliases": ["HONG KONG", "ГОНКОНГ", "🇭🇰"], "full": "Hong Kong", "flag": "🇭🇰"},
    "IS": {"aliases": ["ICELAND", "ИСЛАНДИЯ", "🇮🇸"], "full": "Iceland", "flag": "🇮🇸"},
    "AL": {"aliases": ["ALBANIA", "АЛБАНИЯ", "🇦🇱"], "full": "Albania", "flag": "🇦🇱"},
    "CO": {"aliases": ["COLOMBIANA", "КОЛУМБИЯ", "🇨🇴"], "full": "Colombiana", "flag": "🇨🇴"},
    "MD": {"aliases": ["MOLDOVA", "МОВДОА", "🇲🇩"], "full": "Moldova", "flag": "🇲🇩"},
    "HU": {"aliases": ["HUNGARY", "ВЕНГРИЯ", "🇭🇺"], "full": "Hungary", "flag": "🇭🇺"},
    "ES": {"aliases": ["SPAIN", "ИСПАНИЯ", "🇪🇸"], "full": "Spain", "flag": "🇪🇸"},
    "IR": {"aliases": ["IRAN", "ИРАН", "🇮🇷"], "full": "Iran", "flag": "🇮🇷"},
    "KR": {"aliases": ["ROK", "KOREA", "ЮЖНАЯ КОРЕЯ", "🇰🇷"], "full": "South Korea", "flag": "🇰🇷"},
    "MY": {"aliases": ["MALAYSIA", "МАЛАЙЗИЯ", "🇲🇾"], "full": "Malaysia", "flag": "🇲🇾"},
    "AE": {"aliases": ["UAE", "UNITED ARAB EMIRATES", "ОАЭ", "🇦🇪"], "full": "UAE", "flag": "🇦🇪"},
}

lock = threading.Lock()
api_semaphore = threading.Semaphore(3)
stop_event = threading.Event() 
ip_cache = {}
failed_subnets = {} 
last_api_call = 0

def is_valid_ipv4(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except: return False

def is_technically_broken(link):
    l = link.lower()
    if "type=" not in l: return True
    if "type=http" in l and "type=httpupgrade" not in l: return True
    if "type=splithttp" in l: return True
    if ":443/?" in l or ":80/?" in l or "/??" in l: return True
    if "vless://" in l and not re.search(r'vless://([a-f0-9\-]{32,36})@', l): return True
    if "pbk=" in l and ("security=tls" in l or ":80?" in l): return True            
    if "flow=xtls-rprx-vision" in l and "type=tcp" not in l: return True
    h_m = re.search(r'@([^:/?#\s]+):(\d+)', l)
    if h_m and not (1 <= int(h_m.group(2)) <= 65535): return True
    return False

def fast_ping(host, port, sni):
    try:
        start = time.perf_counter()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=1.1) as sock:
            with context.wrap_socket(sock, server_hostname=sni if sni else None) as ssock:
                return int((time.perf_counter() - start) * 1000)
    except: return None

def full_ping_analysis(host, port, sni, initial_ping):
    pings = [initial_ping]
    try:
        for _ in range(2):
            if stop_event.is_set(): return None
            time.sleep(0.15)
            p = fast_ping(host, port, sni)
            if p: pings.append(p)
        if len(pings) < 3: return None
        avg = sum(pings) // len(pings)
        jit = sum(abs(p - avg) for p in pings) // len(pings)
        return (avg, jit) if jit <= (avg * MAX_JITTER_RATIO) else None
    except: return None

def get_config_details(link):
    try:
        name = requests.utils.unquote(link.split("#")[1]) if "#" in link else ""
        clean_link = re.sub(r'[^\x20-\x7E]', '', link).strip()
        cid_match = re.search(r'://([^@]+)@', clean_link)
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', clean_link)
        s_m = re.search(r'[?&]sni=([^&#\s]*)', clean_link)
        if h_m and is_valid_ipv4(h_m.group(1)):
            sni = s_m.group(1).lower().split('?')[0].split('&')[0] if s_m else ""
            return h_m.group(1), int(h_m.group(2)), sni, cid_match.group(1) if cid_match else "", name
    except: pass
    return None, None, None, None, None

def check_isp_info(ip_str):
    global last_api_call
    with lock:
        if ip_str in ip_cache: return ip_cache[ip_str]
    with api_semaphore:
        try:
            for _ in range(2):
                if stop_event.is_set(): return None, None, False
                with lock:
                    elapsed = time.perf_counter() - last_api_call
                    if elapsed < 1.4: time.sleep(1.4 - elapsed)
                    last_api_call = time.perf_counter()
                resp = session.get(f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,isp,org,as,asname,hosting", timeout=5)
                r = resp.json()
                if r.get("status") == "success":
                    info = f"{r.get('isp')} {r.get('org')} {r.get('as')} {r.get('asname')}".lower()
                    is_banned = any(w in info for w in BAD_HOSTING_KEYWORDS) or any(p in info for p in BANNED_ASNAME_PATTERNS)
                    res = (r.get("countryCode"), info, "BANNED" if is_banned else r.get("hosting", False))
                    with lock: ip_cache[ip_str] = res
                    return res
                break
        except: pass
        return None, None, False

def apply_clean_params(config_link):
    parts = config_link.split("#", 1)
    base = re.sub(r'[&?](?:fp|udp443)=[^&?#]+', '', parts[0])
    sep = "&" if "?" in base else "?"
    base = f"{base}{sep}fp=random".replace("?&", "?").replace("&&", "&").replace("//", "/").replace(":/", "://")
    return f"{base}#{parts[1]}" if len(parts) > 1 else base

def rename_config(link, cc, idx, is_h=False, is_ws=False):
    c = COUNTRY_MAP.get(cc, {"full": cc, "flag": "🌐"})
    tags = []
    if is_h is True: tags.append("HOST")
    if is_ws: tags.append("SNI-RU")
    tag_str = f" [{'|'.join(tags)}]" if tags else ""    
    new_name = f"{c.get('flag', '🌐')} {c.get('full', cc)} — #{idx}{tag_str}"    
    encoded_name = requests.utils.quote(new_name)
    base_url = link.split('#')[0]   
    return f"{base_url}#{encoded_name}"
    
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
    
    sni_domains = set()
    extra_urls, std_urls, gh_repo = [], [], None
    try: gh_repo = Github(auth=Auth.Token(GITHUB_TOKEN)).get_repo(REPO_NAME)
    except: pass

    try:
        src = session.get(REMOTE_SOURCE_URL, timeout=10).text
        def get_list(var):
            m = re.search(rf'{var}\s*=\s*\[(.*?)\]', src, re.S | re.I)
            return re.findall(r'["\']([^"\']+)["\']', m.group(1)) if m else []
        extra_urls, std_urls = get_list("EXTRA_URLS_FOR_26"), get_list("URLS")
        sni_domains.update(s.lower() for s in get_list("SNI_DOMAINS"))
        sni_domains.update([l.strip().lower() for l in session.get(SECONDARY_WHITELIST_URL).text.splitlines() if l.strip()])
    except: pass

    vlm_results, vlm2_results = [], []
    seen_ips, sub_cnt, id_cnt, cc_cnt = set(), {}, {}, {}
    sni_usage_cnt = {} 
    
    ru_vlm_cnt = 0
    ru_vlm2_cnt = 0
    x_cnt = 0 

    def validate(config, is_prio, is_white):
        nonlocal ru_vlm_cnt, ru_vlm2_cnt, x_cnt
        if stop_event.is_set(): return
        is_x = "xhttp" in config.lower()
        is_ru_pot = any(a in config.upper() for a in COUNTRY_MAP["RU"]["aliases"])

        with lock:
            if is_x:
                if x_cnt >= MAX_XHTTP: return
                if is_ru_pot and ru_vlm2_cnt >= MAX_RU_CONFIGS: return
            else:
                v_needs_ru = (is_ru_pot and ru_vlm_cnt < MAX_RU_CONFIGS)
                v2_needs_ru = (is_ru_pot and ru_vlm2_cnt < MAX_RU_CONFIGS)
                if not (v_needs_ru or v2_needs_ru or len(vlm_results) < MAX_CONFIGS + 2 or len(vlm2_results) < MAX_CONFIGS + 2): return

        if is_technically_broken(config): return
        host, port, sni, cid, name = get_config_details(config)
        if not host or not sni: return

        with lock:
            if host in seen_ips or (sni in sni_domains) != is_white: return
            if any(exc in sni for exc in EXCLUDED_SNI_DOMAINS): return
            sni_limit = MAX_SAME_SNI_RU if (is_ru_pot and is_white) else MAX_SAME_SNI_WORLD
            if sni_usage_cnt.get(sni, 0) >= sni_limit: return
            sub = ".".join(host.split(".")[:3])
            if sub_cnt.get(sub, 0) >= MAX_PER_SUBNET or id_cnt.get(cid, 0) >= MAX_PER_ID: return
            if failed_subnets.get(sub, 0) >= MAX_FAILED_PER_SUBNET: return

        p1 = fast_ping(host, port, sni)
        
        # Пункт 2: Валидация границ пинга
        min_p = MIN_RU_PING if is_ru_pot else MIN_WORLD_PING
        max_p = (MAX_RU_PING_XHTTP if is_x else MAX_RU_PING) if is_ru_pot else (MAX_WORLD_PING_XHTTP if is_x else MAX_WORLD_PING)
        
        if not p1 or p1 > max_p or p1 < min_p:
            if not p1 or p1 > max_p:
                with lock: failed_subnets[sub] = failed_subnets.get(sub, 0) + 1
            return
            
        cc, isp, h_stat = check_isp_info(host)
        if not cc or h_stat == "BANNED" or stop_event.is_set(): return
        is_ru = (cc == "RU")
        if is_ru != is_ru_pot: return
        
        full = full_ping_analysis(host, port, sni, p1)
        if not full or full[1] > MAX_JITTER or not (min_p <= full[0] <= max_p): return

        with lock:
            if host in seen_ips: return
            entry = {"link": apply_clean_params(config), "ping": full[0], "country": cc, "is_priority": is_prio, "white_sni": is_white, "is_hosting": h_stat, "is_xhttp": is_x}
            
            added_v, added_v2 = False, False
            if is_x:
                if x_cnt < MAX_XHTTP and (not is_ru or ru_vlm2_cnt < MAX_RU_CONFIGS):
                    vlm2_results.append(entry)
                    x_cnt += 1
                    if is_ru: ru_vlm2_cnt += 1
                    added_v2 = True
            else:
                if (is_ru and ru_vlm_cnt < MAX_RU_CONFIGS) or (not is_ru and len(vlm_results) < MAX_CONFIGS + 2):
                    vlm_results.append(entry)
                    if is_ru: ru_vlm_cnt += 1
                    added_v = True
                if (is_ru and ru_vlm2_cnt < MAX_RU_CONFIGS) or (not is_ru and len(vlm2_results) < MAX_CONFIGS):
                    vlm2_results.append(entry)
                    if is_ru: ru_vlm2_cnt += 1
                    added_v2 = True
            
            if added_v or added_v2:
                seen_ips.add(host)
                sni_usage_cnt[sni] = sni_usage_cnt.get(sni, 0) + 1
                if not is_ru: cc_cnt[cc] = cc_cnt.get(cc, 0) + 1
                sub_cnt[sub], id_cnt[cid] = sub_cnt.get(sub, 0) + 1, id_cnt.get(cid, 0) + 1
                print(f"[FOUND{' (X)' if is_x else ''}] {cc} | {full[0]}ms | {host}", flush=True)
            
            if ru_vlm_cnt >= MIN_RU_CONFIGS and ru_vlm2_cnt >= MIN_RU_CONFIGS and x_cnt >= MAX_XHTTP and len(vlm_results) >= MAX_CONFIGS:
                stop_event.set()

    def fetch_group_data(urls):
        raw = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(fetch_raw_configs, u) for u in set(urls)]
            for f in concurrent.futures.as_completed(futures): raw.extend(f.result())
        unique = list(set(raw)); random.shuffle(unique); return unique

    raw_extra, raw_std = fetch_group_data(extra_urls), fetch_group_data(std_urls)
    order = [(raw_extra, True, True), (raw_std, False, True), (raw_extra, True, False), (raw_std, False, False)]
    for group, prio, white in order:
        if stop_event.is_set(): break
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as v:
            for c in group:
                if stop_event.is_set(): break
                v.submit(validate, c, prio, white)

    def finalize_list(results, is_v2=False):
        all_ru_sni = sorted([r for r in results if r['country'] == 'RU' and r['white_sni']], key=lambda x: x['ping'])
        top_fixed = all_ru_sni[:MAX_TOP_RU_SNI]
        rem_ru_sni = all_ru_sni[MAX_TOP_RU_SNI:]
        x_bucket = sorted([r for r in results if r.get('is_xhttp')], key=lambda x: x['ping']) if is_v2 else []
        
        buckets = {i: [] for i in range(4)}
        for r in results:
            if r in top_fixed or r in x_bucket or (r['country'] == 'RU' and r['white_sni']): continue
            b_idx = (0 if r['white_sni'] else 1) if r['is_priority'] else (2 if r['white_sni'] else 3)
            buckets[b_idx].append(r)
        
        for i in range(4): buckets[i].sort(key=lambda x: x['ping'])
        final, cur_ru_sni = list(top_fixed), len(top_fixed)
        srcs = [x_bucket, buckets[0], rem_ru_sni, buckets[2], buckets[1], buckets[3]] if is_v2 else [buckets[0], rem_ru_sni, buckets[2], buckets[1], buckets[3]]
        
        while len(final) < MAX_CONFIGS:
            added = False
            for s in srcs:
                is_sni_ru_src = (s is rem_ru_sni or s is buckets[0] or s is buckets[2])
                c = 0
                while c < INTERLEAVE_STEP and len(final) < MAX_CONFIGS and s:
                    if is_sni_ru_src and cur_ru_sni >= MAX_TOTAL_SNI_RU: break
                    cfg = s.pop(0)
                    if cfg not in final:
                        final.append(cfg); c += 1; added = True
                        if is_sni_ru_src: cur_ru_sni += 1
            if not added: break
        speed = {r['link']: rk + 1 for rk, r in enumerate(sorted(final, key=lambda x: x['ping']))}
        return [rename_config(r['link'], r['country'], speed[r['link']], r['is_hosting'], r['white_sni']) for r in final]
        
    if gh_repo:
        for fn, res in [(FILENAME_VLM, vlm_results), (FILENAME_VLM2, vlm2_results)]:
            out = finalize_list(res, is_v2=(fn == FILENAME_VLM2))
            path, content = f"githubmirror/{fn}", "\n".join(out)
            try:
                sha = gh_repo.get_contents(path).sha
                gh_repo.update_file(path, f"🚀 {fn} | {len(out)} | {offset}", content, sha)
            except: gh_repo.create_file(path, f"🚀 {fn} | {len(out)} | {offset}", content)
    print(f"--- 🏁 ГОТОВО за {time.perf_counter() - start_total:.1f}с ---")

if __name__ == "__main__":
    main()
