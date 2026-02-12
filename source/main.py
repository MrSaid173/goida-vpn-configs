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

# ЛИМИТЫ XHTTP (ДЛЯ VLM2)
MIN_XHTTP = 5   
MAX_XHTTP = 5  

MAX_JITTER = 50  
MAX_CONFIGS = 50 
INTERLEAVE_STEP = 3 
EXCLUDED_SNI_DOMAINS = ["vk"]
BAD_HOSTING_KEYWORDS = ["cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google", "microsoft", "ovh", "linode", "servers", "work", "oracle", "leaseweb", "mevspace", "m247", "akamai", "host"]

MAX_TOTAL_SNI_RU = MAX_CONFIGS // 2
MAX_TOP_RU_SNI = 5
MAX_RU_CONFIGS = 5
MAX_PER_COUNTRY = 15 
MAX_PER_SUBNET = 3 
MAX_PER_ID = 6
MAX_FAILED_PER_SUBNET = 4 

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
    "MD": {"aliases": ["MOLDOVA", "МОЛДОВА", "🇲🇩"], "full": "Moldova", "flag": "🇲🇩"},
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
    if "host=" in l or "packetencoding=" in l or "type=raw" in l: return True
    if "pbk=" in l:
        if "security=tls" in l or ":80?" in l or "type=" not in l: return True
    if "flow=xtls-rprx-vision" in l and "type=tcp" not in l: return True
    return False

def fast_ping(host, port, sni):
    try:
        start = time.perf_counter()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=1.2) as sock:
            with context.wrap_socket(sock, server_hostname=sni if sni else None) as ssock:
                return int((time.perf_counter() - start) * 1000)
    except: return None

def full_ping_analysis(host, port, sni, initial_ping):
    pings = [initial_ping]
    try:
        for _ in range(2):
            if stop_event.is_set(): return None
            p = fast_ping(host, port, sni)
            if p: pings.append(p)
        if not pings: return None
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
        s_m = re.search(r'[?&]sni=([^&#\s]*)', clean_link)
        sni = s_m.group(1).lower().split('?')[0].split('&')[0] if s_m else ""
        if h_m and is_valid_ipv4(h_m.group(1)):
            return h_m.group(1), int(h_m.group(2)), sni, cid, name
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
                    full_info = f"{r.get('isp')} {r.get('org')} {r.get('as')} {r.get('asname')}".lower()
                    is_banned = any(word in full_info for word in BAD_HOSTING_KEYWORDS)
                    res = (r.get("countryCode"), full_info, "BANNED" if is_banned else r.get("hosting", False))
                    with lock: ip_cache[ip_str] = res
                    return res
                break
        except: pass
        return None, None, False

def apply_clean_params(config_link):
    parts = config_link.split("#", 1)
    base = re.sub(r'[&?](?:fp|udp443)=[^&?#]+', '', parts[0])
    sep = "&" if "?" in base else "?"
    base = f"{base}{sep}fp=random"
    base = base.replace("?&", "?").replace("&&", "&").replace("//", "/").replace(":/", "://")
    return f"{base}#{parts[1]}" if len(parts) > 1 else base

def rename_config(link, country_code, index, is_hosting=False, is_white_sni=False):
    country_info = COUNTRY_MAP.get(country_code, {"full": country_code, "flag": "🌐"})
    tags = []
    if is_hosting is True: tags.append("HOST")
    if is_white_sni: tags.append("SNI-RU")
    tag_str = f" [{'|'.join(tags)}]" if tags else ""
    new_name = f"{country_info['flag']} {country_info['full']} — #{index}{tag_str}"
    return f"{link.split('#')[0]}#{requests.utils.quote(new_name)}"

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
    
    sni_domains, extra_urls, std_urls, gh_repo = set(), [], [], None
    try: gh_repo = Github(auth=Auth.Token(GITHUB_TOKEN)).get_repo(REPO_NAME)
    except: pass

    try:
        src_text = session.get(REMOTE_SOURCE_URL, timeout=10).text
        def get_list(var):
            m = re.search(rf'{var}\s*=\s*\[(.*?)\]', src_text, re.S | re.I)
            return re.findall(r'["\']([^"\']+)["\']', m.group(1)) if m else []
        extra_urls, std_urls = get_list("EXTRA_URLS_FOR_26"), get_list("URLS")
        sni_domains.update(s.lower() for s in get_list("SNI_DOMAINS"))
        sec_text = session.get(SECONDARY_WHITELIST_URL, timeout=10).text
        sni_domains.update([l.strip().lower() for l in sec_text.splitlines() if l.strip()])
    except: pass

    vlm_results, vlm2_results = [], []
    seen_ips, subnet_counts, id_counts, country_counts, ru_count = set(), {}, {}, {}, 0
    xhttp_count = 0 

    def validate(config, is_priority, is_white):
        nonlocal ru_count, xhttp_count
        if stop_event.is_set(): return

        # 1. Быстрый технический фильтр
        if is_technically_broken(config): return
        host, port, sni, cid, name = get_config_details(config)
        if not host or not sni: return
        is_xhttp = "xhttp" in config.lower()

        # 2. ПРОВЕРКА ЛИМИТОВ В ПРОЦЕССЕ (ДО ТЯЖЕЛЫХ ОПЕРАЦИЙ)
        with lock:
            total_v2 = len(vlm2_results)
            # Если это обычный конфиг, проверяем, не нужно ли придержать место для xhttp
            if not is_xhttp:
                needed_xhttp = max(0, MIN_XHTTP - xhttp_count)
                if total_v2 >= (MAX_CONFIGS - needed_xhttp):
                    return # Сбрасываем обычный, так как нужны xhttp

            # Если это xhttp, проверяем не перебрали ли мы их
            if is_xhttp and xhttp_count >= MAX_XHTTP:
                return

            # Проверка глобальных лимитов
            if total_v2 >= MAX_CONFIGS + 2 and len(vlm_results) >= MAX_CONFIGS + 2:
                stop_event.set()
                return

            # Проверка IP и SNI
            if host in seen_ips or (sni in sni_domains) != is_white: return
            if any(exc in sni for exc in EXCLUDED_SNI_DOMAINS): return
            subnet = ".".join(host.split(".")[:3])
            if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET or id_counts.get(cid, 0) >= MAX_PER_ID: return
            if failed_subnets.get(subnet, 0) >= MAX_FAILED_PER_SUBNET: return

        # 3. ТОЛЬКО ТЕПЕРЬ ПИНГ И ISP
        p1 = fast_ping(host, port, sni)
        if not p1 or p1 > MAX_WORLD_PING:
            with lock: failed_subnets[subnet] = failed_subnets.get(subnet, 0) + 1
            return
            
        ip_cc, ip_isp, ip_h_stat = check_isp_info(host)
        if not ip_cc or ip_h_stat == "BANNED" or stop_event.is_set(): return
        is_ru = (ip_cc == "RU")
        if is_ru != any(a in name.upper() for a in COUNTRY_MAP["RU"]["aliases"]): return
        
        full = full_ping_analysis(host, port, sni, p1)
        if not full or full[1] > MAX_JITTER: return

        # 4. ФИНАЛЬНОЕ ДОБАВЛЕНИЕ (ПОД ЛОКОМ)
        with lock:
            if len(vlm2_results) >= MAX_CONFIGS + 5 and len(vlm_results) >= MAX_CONFIGS + 5:
                stop_event.set()
                return
            if is_ru and ru_count >= MAX_RU_CONFIGS: return
            if not is_ru and country_counts.get(ip_cc, 0) >= MAX_PER_COUNTRY: return
            if host in seen_ips: return
            
            seen_ips.add(host)
            res_entry = {
                "link": apply_clean_params(config), "ping": full[0], "country": ip_cc, 
                "is_priority": is_priority, "white_sni": is_white, "is_hosting": ip_h_stat,
                "is_xhttp": is_xhttp
            }
            
            if len(vlm2_results) < MAX_CONFIGS + 5: 
                vlm2_results.append(res_entry)
                if is_xhttp: xhttp_count += 1
            
            if not is_xhttp and len(vlm_results) < MAX_CONFIGS + 5: 
                vlm_results.append(res_entry)

            if is_ru: ru_count += 1
            else: country_counts[ip_cc] = country_counts.get(ip_cc, 0) + 1
            subnet_counts[subnet], id_counts[cid] = subnet_counts.get(subnet, 0) + 1, id_counts.get(cid, 0) + 1
            print(f"[FOUND{' (X)' if is_xhttp else ''}] {ip_cc} | {full[0]}ms | {host}", flush=True)

    def fetch_group_data(urls):
        raw = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(fetch_raw_configs, u) for u in set(urls)]
            for f in concurrent.futures.as_completed(futures): raw.extend(f.result())
        unique = list(set(raw))
        random.shuffle(unique)
        return unique

    raw_extra, raw_std = fetch_group_data(extra_urls), fetch_group_data(std_urls)
    check_order = [(raw_extra, True, True), (raw_std, False, True), (raw_extra, True, False), (raw_std, False, False)]

    for group, priority, white in check_order:
        if stop_event.is_set(): break
        workers = min(len(group), 40) if group else 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as v:
            for c in group:
                if stop_event.is_set(): break
                v.submit(validate, c, priority, white)

    def finalize_list(results, is_vlm2=False):
        top_ru = sorted([r for r in results if r['country'] == 'RU' and r['white_sni']], key=lambda x: x['ping'])[:MAX_TOP_RU_SNI]
        top_ru_links = {r['link'] for r in top_ru}
        xhttp_bucket = []
        if is_vlm2:
            xhttp_bucket = sorted([r for r in results if r.get('is_xhttp') and r['link'] not in top_ru_links], key=lambda x: x['ping'])[:MAX_XHTTP]
        
        xhttp_links = {r['link'] for r in xhttp_bucket}
        current_sni_ru_count, buckets = len(top_ru), {i: [] for i in range(4)}
        for r in results:
            if r['link'] in top_ru_links or r['link'] in xhttp_links: continue
            b_idx = (0 if r['white_sni'] else 1) if r['is_priority'] else (2 if r['white_sni'] else 3)
            buckets[b_idx].append(r)
        for i in range(4): buckets[i].sort(key=lambda x: x['ping'])
        
        final_list = top_ru + xhttp_bucket
        others = []
        while (len(final_list) + len(others)) < MAX_CONFIGS:
            added = False
            for i in range(4):
                is_w = (i == 0 or i == 2)
                for _ in range(INTERLEAVE_STEP):
                    if (len(final_list) + len(others)) >= MAX_CONFIGS: break
                    if buckets[i]:
                        if is_w and current_sni_ru_count >= MAX_TOTAL_SNI_RU: break 
                        config = buckets[i].pop(0)
                        others.append(config)
                        added = True
                        if is_w: current_sni_ru_count += 1
                    else: break
            if not added: break
        final = (final_list + others)[:MAX_CONFIGS]
        speed_rating = {r['link']: rank + 1 for rank, r in enumerate(sorted(final, key=lambda x: x['ping']))}
        return [rename_config(r['link'], r['country'], speed_rating[r['link']], r['is_hosting'], r['white_sni']) for r in final]

    if gh_repo:
        for fn, res in [(FILENAME_VLM, vlm_results), (FILENAME_VLM2, vlm2_results)]:
            output = finalize_list(res, is_vlm2=(fn == FILENAME_VLM2))
            path, content = f"githubmirror/{fn}", "\n".join(output)
            try:
                sha = gh_repo.get_contents(path).sha
                gh_repo.update_file(path, f"🚀 {fn} | {len(output)} | {offset}", content, sha)
            except: gh_repo.create_file(path, f"🚀 {fn} | {len(output)} | {offset}", content)

    print(f"--- 🏁 ГОТОВО за {time.perf_counter() - start_total:.1f}с ---")

if __name__ == "__main__":
    main()
        
