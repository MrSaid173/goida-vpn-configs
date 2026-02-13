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
MIN_XHTTP, MAX_XHTTP = 5, 5
MIN_RU_CONFIGS, MAX_RU_CONFIGS = 5, 5
MAX_CONFIGS = 50
INTERLEAVE_STEP = 3
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
MAX_JITTER, MAX_JITTER_RATIO = 50, 0.4
MIN_RU_PING, MAX_RU_PING = 90.0, 400.0
MIN_WORLD_PING, MAX_WORLD_PING = 25.0, 500.0
MAX_RU_PING_XHTTP, MAX_WORLD_PING_XHTTP = 550.0, 650.0
MAX_PER_SUBNET, MAX_PER_ID, MAX_FAILED_PER_SUBNET = 3, 6, 4
MAX_SAME_SNI_RU, MAX_SAME_SNI_WORLD = 2, 15
MAX_TOTAL_SNI_RU, MAX_TOP_RU_SNI = 25, 5
EXCLUDED_SNI_DOMAINS = ["userapi"]

# --- СТАТИСТИКА ---
STATS = {
    "raw_found": 0, "unique_after_sets": 0, "processed": 0,
    "dropped": {
        "broken": 0, "sni_mismatch": 0, "limits_subnet_id": 0, "limits_sni_usage": 0,
        "ping_timeout_or_range": 0, "banned_hosting": 0, "jitter_high": 0, "country_mismatch": 0
    },
    "pings": [], "zero_pings": 0, "fast_pings_low": 0 # < 5ms
}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
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
    "SK": {"aliases": ["SLOVAKIA", "СЛОВАКИЯ", "🇸🇰"], "full": "Slovakia", "flag": "🇸🇰"},
}

lock = threading.Lock()
api_semaphore = threading.Semaphore(3)
stop_event = threading.Event() 
ip_cache, failed_subnets, last_api_call = {}, {}, 0

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
        if p is not None: pings.append(p)
    if len(pings) < 3: return None
    avg = sum(pings) // len(pings)
    jit = sum(abs(p - avg) for p in pings) // len(pings)
    return (avg, jit) if jit <= (avg * MAX_JITTER_RATIO) else None

def get_config_details(link):
    try:
        clean_link = re.sub(r'[^\x20-\x7E]', '', link).strip()
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', clean_link)
        s_m = re.search(r'[?&]sni=([^&#\s]*)', clean_link)
        cid_match = re.search(r'://([^@]+)@', clean_link)
        if h_m and is_valid_ipv4(h_m.group(1)):
            sni = s_m.group(1).lower().split('?')[0].split('&')[0] if s_m else ""
            return h_m.group(1), int(h_m.group(2)), sni, cid_match.group(1) if cid_match else "", (link.split("#")[1] if "#" in link else "")
    except: pass
    return None, None, None, None, None

def check_isp_info(ip_str):
    global last_api_call
    with lock:
        if ip_str in ip_cache: return ip_cache[ip_str]
    with api_semaphore:
        try:
            for _ in range(2):
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

def rename_config(link, cc, idx, is_h=False, is_ws=False):
    c = COUNTRY_MAP.get(cc, {"full": cc, "flag": "🌐"})
    tags = ["HOST"] if is_h is True else []
    if is_ws: tags.append("SNI-RU")
    tag_str = f" [{'|'.join(tags)}]" if tags else ""    
    new_name = f"{c.get('flag', '🌐')} {c.get('full', cc)} — #{idx}{tag_str}"    
    return f"{link.split('#')[0]}#{requests.utils.quote(new_name)}"

def validate(config, is_prio, is_white, sni_domains, ru_counters, results_v1, results_v2, seen_ips, sub_cnt, id_cnt, sni_usage_cnt):
    if stop_event.is_set(): return
    with lock: STATS["processed"] += 1
    
    if is_technically_broken(config):
        with lock: STATS["dropped"]["broken"] += 1
        return
    
    host, port, sni, cid, name = get_config_details(config)
    if not host or not sni: return
    is_ru_pot = any(a in name.upper() for a in COUNTRY_MAP["RU"]["aliases"])
    is_x = "xhttp" in config.lower()

    with lock:
        if host in seen_ips or (sni in sni_domains) != is_white:
            STATS["dropped"]["sni_mismatch"] += 1
            return
        sub = ".".join(host.split(".")[:3])
        if sub_cnt.get(sub, 0) >= MAX_PER_SUBNET or id_cnt.get(cid, 0) >= MAX_PER_ID or failed_subnets.get(sub, 0) >= MAX_FAILED_PER_SUBNET:
            STATS["dropped"]["limits_subnet_id"] += 1
            return
        sni_limit = MAX_SAME_SNI_RU if (is_ru_pot and is_white) else MAX_SAME_SNI_WORLD
        if sni_usage_cnt.get(sni, 0) >= sni_limit:
            STATS["dropped"]["limits_sni_usage"] += 1
            return

    p1 = fast_ping(host, port, sni)
    min_p = MIN_RU_PING if is_ru_pot else MIN_WORLD_PING
    max_p = (MAX_RU_PING_XHTTP if is_x else MAX_RU_PING) if is_ru_pot else (MAX_WORLD_PING_XHTTP if is_x else MAX_WORLD_PING)

    if not p1 or p1 > max_p or p1 < min_p:
        with lock: 
            STATS["dropped"]["ping_timeout_or_range"] += 1
            if not p1 or p1 > max_p: failed_subnets[sub] = failed_subnets.get(sub, 0) + 1
        return

    cc, isp, h_stat = check_isp_info(host)
    if not cc or h_stat == "BANNED":
        with lock: STATS["dropped"]["banned_hosting" if h_stat == "BANNED" else "ping_timeout_or_range"] += 1
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
        STATS["pings"].append(full[0])
        entry = {"link": config.split("#")[0] + "?fp=random#" + name, "ping": full[0], "country": cc, "is_priority": is_prio, "white_sni": is_white, "is_hosting": h_stat, "is_xhttp": is_x}
        
        added = False
        if is_x and ru_counters["x"] < MAX_XHTTP:
            results_v2.append(entry); ru_counters["x"] += 1; added = True
        else:
            if (cc == "RU" and ru_counters["v1_ru"] < MAX_RU_CONFIGS) or (cc != "RU" and len(results_v1) < MAX_CONFIGS):
                results_v1.append(entry); added = True
                if cc == "RU": ru_counters["v1_ru"] += 1
            if (cc == "RU" and ru_counters["v2_ru"] < MAX_RU_CONFIGS) or (cc != "RU" and len(results_v2) < MAX_CONFIGS):
                results_v2.append(entry); added = True
                if cc == "RU": ru_counters["v2_ru"] += 1

        if added:
            seen_ips.add(host); sub_cnt[sub] = sub_cnt.get(sub, 0) + 1; id_cnt[cid] = id_cnt.get(cid, 0) + 1
            sni_usage_cnt[sni] = sni_usage_cnt.get(sni, 0) + 1
            print(f"[+] {cc} | {full[0]}ms | {host}")

def main():
    start_total = time.perf_counter()
    print(f"--- 🟢 ЗАПУСК СБОРА СТАТИСТИКИ ---")
    
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
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
            futs = [ex.submit(lambda u: [l.strip() for l in re.findall(r'(?:vless|ssr|tuic|hysteria|hysteria2)://[^\s]+', session.get(u).text)], url) for url in urls]
            for f in concurrent.futures.as_completed(futs): raw.extend(f.result())
        with lock: STATS["raw_found"] = len(raw)
        u = list(set(raw)); random.shuffle(u)
        with lock: STATS["unique_after_sets"] = len(u)
        return u

    all_configs = fetch_all(extra_urls + std_urls)
    v1_res, v2_res = [], []
    seen_ips, sub_cnt, id_cnt, sni_usage, ru_c = set(), {}, {}, {}, {"v1_ru": 0, "v2_ru": 0, "x": 0}

    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as v:
        for c in all_configs:
            v.submit(validate, c, True, True, sni_domains, ru_c, v1_res, v2_res, seen_ips, sub_cnt, id_cnt, sni_usage)

    # --- ИТОГОВЫЙ ОТЧЕТ ---
    duration = time.perf_counter() - start_total
    avg_ping = sum(STATS["pings"])/len(STATS["pings"]) if STATS["pings"] else 0
    
    print(f"\n{'='*40}\n📊 ДЕТАЛЬНАЯ СТАТИСТИКА:\n{'='*40}")
    print(f"🔹 Собрано ссылок: {STATS['raw_found']}")
    print(f"🔹 Уникальных после фильтра: {STATS['unique_after_sets']}")
    print(f"🔹 Обработано потоками: {STATS['processed']}")
    print(f"--- Причины отсева ---")
    for k, v in STATS["dropped"].items(): print(f"  ❌ {k}: {v}")
    print(f"--- Пинг-аналитика ---")
    print(f"  ✅ Средний пинг: {avg_ping:.1f}ms")
    print(f"  ⚠️ Конфигов с 0ms: {STATS['zero_pings']}")
    print(f"  🚀 Конфигов < 5ms: {STATS['fast_pings_low']}")
    print(f"⏱ Время выполнения: {duration:.1f}с")
    print(f"{'='*40}")

if __name__ == "__main__":
    main()
