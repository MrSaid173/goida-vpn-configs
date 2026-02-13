import os, re, requests, urllib3, concurrent.futures, ipaddress, base64, json, time, socket, ssl, random
from datetime import datetime
import zoneinfo
import threading

# --- НАСТРОЙКИ ---
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MrSaid173/golden-paths_configs"
FILENAME_VLM = "vlm"
FILENAME_VLM2 = "vlm2"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
SECONDARY_WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt"

# --- ЛИМИТЫ ---
MIN_XHTTP, MAX_XHTTP = 5, 5
MIN_RU_CONFIGS, MAX_RU_CONFIGS = 5, 5
MAX_CONFIGS = 50
INTERLEAVE_STEP = 3
BAD_HOSTING_KEYWORDS = ["cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google", "microsoft", "ovh", "linode", "servers", "work", "oracle", "leaseweb", "m247", "akamai", "host"]
BANNED_ASNAME_PATTERNS = ["-ru", "-ua", "-by", "-kz", "-uz", "-ge", "-am", "-az", "-md", "-tj", "-kg", "-tm", "-us", "-ca", "-mx", "-br", "-ar", "-cl", "-co", "-pe", "-ve", "-de", "-nl", "-gb", "-uk", "-fr", "-it", "-es", "-pl", "-at", "-ch", "-se", "-no", "-fi", "-dk", "-ie", "-pt", "-be", "-cz", "-hu", "-ro", "-bg", "-gr", "-tr", "-ee", "-lv", "-lt", "-si", "-sk", "-hr", "-rs", "-me", "-ba", "-al", "-is", "-lu", "-mt", "-cn", "-hk", "-sg", "-jp", "-kr", "-in", "-tw", "-vn", "-th", "-my", "-ph", "-id", "-ae", "-il", "-sa", "-ir", "-iq", "-jo", "-kw", "-qa", "-om", "-ye", "-au", "-nz", "-za", "-ng", "-eg", "-ke", "-ma", "-dz", "-tn"]
MAX_JITTER, MAX_JITTER_RATIO = 50, 0.4
MIN_RU_PING, MAX_RU_PING = 90.0, 480.0
MIN_WORLD_PING, MAX_WORLD_PING = 25.0, 530.0
MAX_RU_PING_XHTTP, MAX_WORLD_PING_XHTTP = 600.0, 650.0
MAX_PER_SUBNET, MAX_PER_ID, MAX_FAILED_PER_SUBNET = 3, 6, 4
MAX_SAME_SNI_RU, MAX_SAME_SNI_WORLD = 2, 15
MAX_TOTAL_SNI_RU, MAX_TOP_RU_SNI = 25, 5
EXCLUDED_SNI_DOMAINS = ["userapi"]

# --- СТАТИСТИКА ---
STATS = {
    "raw_found": 0, "unique_after_sets": 0, "processed_total": 0,
    "api_calls": 0, "zero_pings": 0, "fast_pings_low": 0, "pings": [],
    "dropped": {
        "broken": 0, "sni_mismatch": 0, "excluded_sni": 0, 
        "sni_limit": 0, "subnet_id_limit": 0, "ping_fail": 0, 
        "banned_hosting": 0, "country_mismatch": 0, "jitter_high": 0
    }
}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
lock = threading.Lock()
api_semaphore = threading.Semaphore(3)
stop_event = threading.Event() 
ip_cache, failed_subnets, last_api_call = {}, {}, 0

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
    "SK": {"aliases": ["SLOVAKIA", "СЛОВАКИЯ", "🇸🇰"], "full": "Slovakia", "flag": "🇸🇰"},
}

def is_valid_ipv4(ip):
    try: return bool(ipaddress.IPv4Address(ip))
    except: return False

def is_technically_broken(link):
    l = link.lower()
    if any(x in l for x in ["type=http", "type=splithttp"]) and "type=httpupgrade" not in l: return True
    if "vless://" in l and not re.search(r'vless://([a-f0-9\-]{32,36})@', l): return True
    h_m = re.search(r'@([^:/?#\s]+):(\d+)', l)
    if h_m and not (1 <= int(h_m.group(2)) <= 65535): return True
    return False

def fast_ping(host, port, sni):
    try:
        start = time.perf_counter()
        context = ssl.create_default_context()
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=1.1) as sock:
            with context.wrap_socket(sock, server_hostname=sni if sni else None) as ssock:
                p = int((time.perf_counter() - start) * 1000)
                with lock:
                    if p == 0: STATS["zero_pings"] += 1
                    if p < 5: STATS["fast_pings_low"] += 1
                return p
    except: return None

def full_ping_analysis(host, port, sni, initial_ping):
    pings = [initial_ping]
    for _ in range(2):
        if stop_event.is_set(): return None
        time.sleep(0.1)
        p = fast_ping(host, port, sni)
        if p: pings.append(p)
    if len(pings) < 3: return None
    avg = sum(pings) // len(pings)
    jit = sum(abs(p - avg) for p in pings) // len(pings)
    return (avg, jit) if jit <= (avg * MAX_JITTER_RATIO) else None

def get_config_details(link):
    try:
        clean = re.sub(r'[^\x20-\x7E]', '', link).strip()
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', clean)
        s_m = re.search(r'[?&]sni=([^&#\s]*)', clean)
        cid_m = re.search(r'://([^@]+)@', clean)
        if h_m and is_valid_ipv4(h_m.group(1)):
            sni = s_m.group(1).lower().split('?')[0].split('&')[0] if s_m else ""
            name = (link.split("#")[1] if "#" in link else "")
            return h_m.group(1), int(h_m.group(2)), sni, cid_m.group(1) if cid_m else "", name
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
                    STATS["api_calls"] += 1
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

def validate(config, is_prio, is_white, sni_domains, ru_counters, results, seen_ips, sub_cnt, id_cnt, sni_usage):
    if stop_event.is_set(): return
    with lock: STATS["processed_total"] += 1
    
    if is_technically_broken(config):
        with lock: STATS["dropped"]["broken"] += 1
        return
    
    host, port, sni, cid, name = get_config_details(config)
    if not host or not sni: return
    is_x = "xhttp" in config.lower()
    is_ru_pot = any(a in name.upper() for a in COUNTRY_MAP["RU"]["aliases"])

    with lock:
        if host in seen_ips or (sni in sni_domains) != is_white:
            STATS["dropped"]["sni_mismatch"] += 1
            return
        if any(exc in sni for exc in EXCLUDED_SNI_DOMAINS):
            STATS["dropped"]["excluded_sni"] += 1
            return
        sub = ".".join(host.split(".")[:3])
        if sub_cnt.get(sub, 0) >= MAX_PER_SUBNET or id_cnt.get(cid, 0) >= MAX_PER_ID or failed_subnets.get(sub, 0) >= MAX_FAILED_PER_SUBNET:
            STATS["dropped"]["subnet_id_limit"] += 1
            return
        s_limit = MAX_SAME_SNI_RU if (is_ru_pot and is_white) else MAX_SAME_SNI_WORLD
        if sni_usage.get(sni, 0) >= s_limit:
            STATS["dropped"]["sni_limit"] += 1
            return

    p1 = fast_ping(host, port, sni)
    m_p = (MAX_RU_PING_XHTTP if is_x else MAX_RU_PING) if is_ru_pot else (MAX_WORLD_PING_XHTTP if is_x else MAX_WORLD_PING)
    if not p1 or p1 > m_p:
        with lock: 
            STATS["dropped"]["ping_fail"] += 1
            failed_subnets[sub] = failed_subnets.get(sub, 0) + 1
        return

    cc, _, h_stat = check_isp_info(host)
    if not cc or h_stat == "BANNED":
        with lock: STATS["dropped"]["banned_hosting"] += 1
        return
    if (cc == "RU") != is_ru_pot:
        with lock: STATS["dropped"]["country_mismatch"] += 1
        return

    full = full_ping_analysis(host, port, sni, p1)
    if not full:
        with lock: STATS["dropped"]["jitter_high"] += 1
        return

    with lock:
        if host in seen_ips: return
        # Лимиты наполнения
        if is_x and ru_counters["x"] >= MAX_XHTTP: return
        if cc == "RU" and ru_counters["ru"] >= MAX_RU_CONFIGS and not is_x: return

        entry = {
            "link": config.split("#")[0] + "?fp=random", "name": name, 
            "ping": full[0], "country": cc, "is_priority": is_prio, 
            "white_sni": is_white, "is_hosting": h_stat, "is_xhttp": is_x
        }
        results.append(entry)
        seen_ips.add(host)
        STATS["pings"].append(full[0])
        if is_x: ru_counters["x"] += 1
        if cc == "RU": ru_counters["ru"] += 1
        sub_cnt[sub] = sub_cnt.get(sub, 0) + 1
        id_cnt[cid] = id_cnt.get(cid, 0) + 1
        sni_usage[sni] = sni_usage.get(sni, 0) + 1
        print(f"[+] {cc} | {full[0]}ms | {host}")

def finalize_list(results):
    all_ru_sni = sorted([r for r in results if r['country'] == 'RU' and r['white_sni']], key=lambda x: x['ping'])
    top_fixed = all_ru_sni[:MAX_TOP_RU_SNI]
    
    buckets = {i: [] for i in range(4)}
    for r in results:
        if r in top_fixed: continue
        idx = (0 if r['white_sni'] else 1) if r['is_priority'] else (2 if r['white_sni'] else 3)
        buckets[idx].append(r)
    
    for i in range(4): buckets[i].sort(key=lambda x: x['ping'])
    
    final = list(top_fixed)
    sources = [buckets[0], all_ru_sni[MAX_TOP_RU_SNI:], buckets[2], buckets[1], buckets[3]]
    
    while len(final) < MAX_CONFIGS and any(sources):
        for src in sources:
            for _ in range(INTERLEAVE_STEP):
                if src and len(final) < MAX_CONFIGS:
                    final.append(src.pop(0))
                else: break
    return final

def main():
    start_total = time.perf_counter()
    print(f"--- 🟢 ЗАПУСК СБОРА ---")
    
    sni_domains = set()
    try:
        src = session.get(REMOTE_SOURCE_URL).text
        def g_l(v): return re.findall(r'["\']([^"\']+)["\']', re.search(rf'{v}\s*=\s*\[(.*?)\]', src, re.S).group(1))
        extra_urls, std_urls = g_l("EXTRA_URLS_FOR_26"), g_l("URLS")
        sni_domains.update(s.lower() for s in g_l("SNI_DOMAINS"))
        sni_domains.update([l.strip().lower() for l in session.get(SECONDARY_WHITELIST_URL).text.splitlines() if l.strip()])
    except: return

    def fetch_all(urls):
        raw = []
        for u in urls:
            try: raw.extend(re.findall(r'(?:vless|ssr|tuic|hysteria|hysteria2)://[^\s]+', session.get(u).text))
            except: pass
        return list(set(raw))

    raw_extra, raw_std = fetch_all(extra_urls), fetch_all(std_urls)
    with lock: STATS["raw_found"] = len(raw_extra) + len(raw_std)
    
    v_results = []
    seen_ips, sub_cnt, id_cnt, sni_usage, ru_c = set(), {}, {}, {}, {"ru": 0, "x": 0}

    # СТРОГАЯ ОЧЕРЕДНОСТЬ ПРОВЕРКИ (как в прошлом коде)
    check_order = [
        (raw_extra, True, True),   # Extra источники + White SNI
        (raw_std, False, True),    # Обычные источники + White SNI
        (raw_extra, True, False),  # Extra источники + Other SNI
        (raw_std, False, False)    # Обычные источники + Other SNI
    ]

    for configs, is_prio, is_white in check_order:
        if stop_event.is_set(): break
        random.shuffle(configs)
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
            for c in configs:
                ex.submit(validate, c, is_prio, is_white, sni_domains, ru_c, v_results, seen_ips, sub_cnt, id_cnt, sni_usage)

    final = finalize_list(v_results)
    
    # --- ОТЧЕТ ---
    dur = time.perf_counter() - start_total
    avg = sum(STATS["pings"])/len(STATS["pings"]) if STATS["pings"] else 0
    print(f"\n{'='*40}\n📊 ИТОГОВАЯ СТАТИСТИКА:\n{'='*40}")
    print(f"📥 Найдено ссылок: {STATS['raw_found']}")
    print(f"⚙️ Обработано: {STATS['processed_total']}")
    print(f"✅ В финальном списке: {len(final)}")
    print(f"🌐 Запросов к IP-API: {STATS['api_calls']}")
    print(f"--- Причины отсева ---")
    for k, v in STATS["dropped"].items(): print(f"  ❌ {k}: {v}")
    print(f"⏱ Время выполнения: {dur:.1f}с | Средний пинг: {avg:.1f}ms")

if __name__ == "__main__":
    main()
    
