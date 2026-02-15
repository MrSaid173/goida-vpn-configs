import os
import re
import requests
import urllib3
import concurrent.futures
import ipaddress
import base64
import json
import time
import socket
import ssl
import random
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
MIN_XHTTP = 1   
MAX_XHTTP = 1   
MIN_RU_CONFIGS = 5  
MAX_RU_CONFIGS = 5  
MIN_HOST = 1
MAX_HOST = 10

INTERLEAVE_STEP = 3 
EXCLUDED_SNI_DOMAINS = ["userapi", "splitter.wb.ru"]
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
MAX_EXPOSED_WORLD = 5
MAX_SAME_SNI_RU = 1
MAX_SAME_SNI_WORLD = 5 

MIN_RU_PING, MAX_RU_PING = 90.0, 480.0
MIN_WORLD_PING, MAX_WORLD_PING = 25.0, 550.0
MAX_RU_PING_XHTTP = MAX_RU_PING + 120
MAX_WORLD_PING_XHTTP = MAX_WORLD_PING + 120

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
    except:
        return False

def is_technically_broken(link):
    l = link.lower()
    if "type=" not in l: return True
    if "type=http" in l and "type=httpupgrade" not in l: return True
    if "type=splithttp" in l: return True
    if ":443/?" in l or ":80/?" in l or "/??" in l: return True
    if "host=" in l or "packetencoding=" in l or "type=raw" in l: return True
    if "vless://" in l:
        match = re.search(r'vless://([a-f0-9\-]{32,36})@', l)
        if not match: return True
    if "pbk=" in l:
        if "security=tls" in l or ":80?" in l: return True            
    if "flow=xtls-rprx-vision" in l and "type=tcp" not in l: return True
    
    s_m = re.search(r'[?&]sni=([^&#\s]*)', l)
    h_m = re.search(r'@([^:/?#\s]+):(\d+)', l)  
    if ("security=tls" in l or "security=reality" in l):
        if not s_m: return True
        sni = s_m.group(1)
        if is_valid_ipv4(sni): return True       
    if h_m:
        port = int(h_m.group(2))
        if not (1 <= port <= 65535): return True
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
    except:
        return None

def full_ping_analysis(host, port, sni, initial_ping):
    pings = [initial_ping]
    max_attempts = 3 
    try:
        for _ in range(max_attempts):
            if stop_event.is_set(): return None
            time.sleep(0.15)
            p = fast_ping(host, port, sni)
            if p: pings.append(p)
        if len(pings) < 4: return None
        avg = sum(pings) // len(pings)
        jit = sum(abs(p - avg) for p in pings) // len(pings)
        if jit > (avg * MAX_JITTER_RATIO): return None      
        return avg, jit
    except:
        return None

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
    except:
        pass
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
                    is_banned_hosting = any(word in full_info for word in BAD_HOSTING_KEYWORDS)
                    is_banned_pattern = any(pattern.lower() in full_info for pattern in BANNED_ASNAME_PATTERNS)
                    is_banned = is_banned_pattern or (is_banned_hosting if r.get("countryCode") == "RU" else False)
                    res = (r.get("countryCode"), full_info, "BANNED" if is_banned else r.get("hosting", False))
                    with lock: ip_cache[ip_str] = res
                    return res
                break
        except:
            pass
        return None, None, False

def apply_clean_params(config_link):
    parts = config_link.split("#", 1)
    base = re.sub(r'[&?](?:fp|udp443)=[^&?#]+', '', parts[0])
    sep = "&" if "?" in base else "?"
    base = f"{base}{sep}fp=random"
    base = base.replace("?&", "?").replace("&&", "&").replace("//", "/").replace(":/", "://")
    return f"{base}#{parts[1]}" if len(parts) > 1 else base

def get_exposed_tag(host):
    s = w = False
    try:
        with socket.create_connection((host, 22), timeout=1.0): s = True
    except:
        pass
    try:
        with socket.create_connection((host, 80), timeout=1.0): w = True
    except:
        pass
    if s and w: return "S|W"
    if s: return "S"
    if w: return "W"
    return None

def rename_config(link, country_code, index, is_hosting=False, is_white_sni=False, exp_tag=None):
    country_info = COUNTRY_MAP.get(country_code, {"full": country_code, "flag": "🌐"})
    tags = []
    if is_hosting: tags.append("HOST")
    if is_white_sni: tags.append("SNI-RU")
    if exp_tag: tags.append(exp_tag)
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
    except:
        return []

def main():
    start_total = time.perf_counter()
    print(f"--- 🟢 ЗАПУСК [{offset}] ---", flush=True)
    
    sni_domains = set()
    exposed_world_count = 0
    extra_urls, std_urls, gh_repo = [], [], None
    try:
        gh_repo = Github(auth=Auth.Token(GITHUB_TOKEN)).get_repo(REPO_NAME)
    except:
        pass

    try:
        src_text = session.get(REMOTE_SOURCE_URL, timeout=10).text
        def get_list(var):
            m = re.search(rf'{var}\s*=\s*\[(.*?)\]', src_text, re.S | re.I)
            return re.findall(r'["\']([^"\']+)["\']', m.group(1)) if m else []
        extra_urls, std_urls = get_list("EXTRA_URLS_FOR_26"), get_list("URLS")
        sni_domains.update(s.lower() for s in get_list("SNI_DOMAINS"))
        sec_text = session.get(SECONDARY_WHITELIST_URL, timeout=10).text
        sni_domains.update([l.strip().lower() for l in sec_text.splitlines() if l.strip()])
    except:
        pass

    vlm_results = []
    vlm2_results = []
    seen_ips = set()
    subnet_counts = {}
    id_counts = {}
    country_counts = {}
    sni_usage_counts = {}

    ru_vlm_count = 0
    ru_vlm2_count = 0
    xhttp_count = 0
    hosting_vlm_count = 0
    hosting_vlm2_count = 0

    def validate(config, is_priority, is_white):
        nonlocal ru_vlm_count, ru_vlm2_count, xhttp_count, exposed_world_count, hosting_vlm_count, hosting_vlm2_count
        if stop_event.is_set():
            return

        is_xhttp = "xhttp" in config.lower()
        is_ru_potential = any(a in config.upper() for a in COUNTRY_MAP["RU"]["aliases"])

        with lock:
            if is_xhttp:
                if xhttp_count >= MAX_XHTTP:
                    return
                if is_ru_potential and ru_vlm2_count >= MAX_RU_CONFIGS:
                    return
            else:
                vlm_needs_ru = is_ru_potential and ru_vlm_count < MAX_RU_CONFIGS
                vlm2_needs_ru = is_ru_potential and ru_vlm2_count < MAX_RU_CONFIGS
                if not (vlm_needs_ru or vlm2_needs_ru or len(vlm_results) < MAX_CONFIGS or len(vlm2_results) < MAX_CONFIGS):
                    return

        if is_technically_broken(config):
            return

        host, port, sni, cid, name = get_config_details(config)
        if not host or not sni:
            return

        exp_tag = get_exposed_tag(host)
        if not is_white and exp_tag:
            with lock:
                if exposed_world_count >= MAX_EXPOSED_WORLD:
                    return

        with lock:
            if host in seen_ips or (sni in sni_domains) != is_white:
                return
            if any(exc in sni for exc in EXCLUDED_SNI_DOMAINS):
                return

            sni_limit = MAX_SAME_SNI_RU if (is_ru_potential and is_white) else MAX_SAME_SNI_WORLD
            if sni_usage_counts.get(sni, 0) >= sni_limit:
                return

            subnet = ".".join(host.split(".")[:3])
            if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET or id_counts.get(cid, 0) >= MAX_PER_ID:
                return         

            if failed_subnets.get(subnet, 0) >= MAX_FAILED_PER_SUBNET:
                return

        p1 = fast_ping(host, port, sni)

        initial_max_p = MAX_WORLD_PING_XHTTP if is_xhttp else MAX_WORLD_PING
        if not p1 or p1 > initial_max_p:
            with lock:
                failed_subnets[subnet] = failed_subnets.get(subnet, 0) + 1
            return

        ip_cc, ip_isp, ip_h_stat = check_isp_info(host)
        if not ip_cc or ip_h_stat == "BANNED" or stop_event.is_set():
            return

        is_ru = (ip_cc == "RU")
        if is_ru != is_ru_potential:
            return

        max_p = MAX_RU_PING_XHTTP if (is_ru and is_xhttp) else (MAX_RU_PING if is_ru else MAX_WORLD_PING)
        if p1 > max_p:
            return

        full = full_ping_analysis(host, port, sni, p1)
        if not full or full[1] > MAX_JITTER:
            return

        with lock:
            if host in seen_ips:
                return

            res_entry = {
                "link": apply_clean_params(config),
                "ping": full[0],
                "country": ip_cc,
                "is_priority": is_priority,
                "white_sni": is_white,
                "is_hosting": ip_h_stat,
                "is_xhttp": is_xhttp,
                "exp_tag": exp_tag
            }

            added = False

            # Проверка лимита HOST перед добавлением
            if res_entry["is_hosting"]:
                if (is_xhttp or not is_ru) and hosting_vlm2_count >= MAX_HOST:
                    return
                if (not is_xhttp and is_ru) and hosting_vlm_count >= MAX_HOST:
                    return

            if is_xhttp:
                if is_ru:
                    if ru_vlm2_count < MAX_RU_CONFIGS and xhttp_count < MAX_XHTTP:
                        vlm2_results.append(res_entry)
                        ru_vlm2_count += 1
                        xhttp_count += 1
                        if res_entry["is_hosting"]:
                            hosting_vlm2_count += 1
                        added = True
                else:
                    if xhttp_count < MAX_XHTTP:
                        vlm2_results.append(res_entry)
                        xhttp_count += 1
                        if res_entry["is_hosting"]:
                            hosting_vlm2_count += 1
                        added = True
            else:
                # vlm
                if is_ru:
                    if ru_vlm_count < MAX_RU_CONFIGS:
                        vlm_results.append(res_entry)
                        ru_vlm_count += 1
                        if res_entry["is_hosting"]:
                            hosting_vlm_count += 1
                        added = True
                elif len(vlm_results) < MAX_CONFIGS:
                    vlm_results.append(res_entry)
                    if res_entry["is_hosting"]:
                        hosting_vlm_count += 1
                    added = True

                # vlm2
                if is_ru:
                    if ru_vlm2_count < MAX_RU_CONFIGS:
                        vlm2_results.append(res_entry)
                        ru_vlm2_count += 1
                        if res_entry["is_hosting"]:
                            hosting_vlm2_count += 1
                        added = True
                elif len(vlm2_results) < MAX_CONFIGS - max(0, MIN_XHTTP - xhttp_count):
                    vlm2_results.append(res_entry)
                    if res_entry["is_hosting"]:
                        hosting_vlm2_count += 1
                    added = True

            if added:
                seen_ips.add(host)
                sni_usage_counts[sni] = sni_usage_counts.get(sni, 0) + 1
                if not is_ru:
                    country_counts[ip_cc] = country_counts.get(ip_cc, 0) + 1
                subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                id_counts[cid] = id_counts.get(cid, 0) + 1
                print(f"[FOUND{' (X)' if is_xhttp else ''}] {ip_cc} | {full[0]}ms | {host}", flush=True)
                if not is_ru and exp_tag:
                    exposed_world_count += 1

            # Условие остановки теперь учитывает HOST
            if (ru_vlm_count >= MIN_RU_CONFIGS and
                ru_vlm2_count >= MIN_RU_CONFIGS and
                xhttp_count >= MIN_XHTTP and
                hosting_vlm_count >= MIN_HOST and
                hosting_vlm2_count >= MIN_HOST and
                len(vlm_results) >= MAX_CONFIGS):
                stop_event.set()

    def fetch_group_data(urls):
        raw = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(fetch_raw_configs, u) for u in set(urls)]
            for f in concurrent.futures.as_completed(futures):
                raw.extend(f.result())
        unique = list(set(raw))
        random.shuffle(unique)
        return unique

    raw_extra = fetch_group_data(extra_urls)
    raw_std = fetch_group_data(std_urls)

    check_order = [
        (raw_extra, True, True),
        (raw_std, False, True),
        (raw_extra, True, False),
        (raw_std, False, False)
    ]

    for group, priority, white in check_order:
        if stop_event.is_set():
            break
        workers = min(len(group), 40) if group else 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as v:
            for c in group:
                if stop_event.is_set():
                    break
                v.submit(validate, c, priority, white)

    def finalize_list(results, is_vlm2=False):
        all_ru_sni = sorted([r for r in results if r['country'] == 'RU' and r['white_sni']], key=lambda x: x['ping'])
        top_fixed = all_ru_sni[:MAX_TOP_RU_SNI]
        remaining_ru_sni = all_ru_sni[MAX_TOP_RU_SNI:]
        
        xhttp_bucket = []
        if is_vlm2:
            xhttp_bucket = sorted([r for r in results if r.get('is_xhttp')], key=lambda x: x['ping'])
        
        buckets = {i: [] for i in range(4)}
        for r in results:
            if r in top_fixed or r in xhttp_bucket or (r['country'] == 'RU' and r['white_sni']):
                continue
            b_idx = (0 if r['white_sni'] else 1) if r['is_priority'] else (2 if r['white_sni'] else 3)
            buckets[b_idx].append(r)
        
        for i in range(4):
            buckets[i].sort(key=lambda x: x['ping'])
        
        final = list(top_fixed)
        current_ru_sni_total = len(top_fixed)
        
        sources_order = []
        if is_vlm2:
            sources_order.append(xhttp_bucket)
        sources_order.extend([buckets[0], remaining_ru_sni, buckets[2], buckets[1], buckets[3]])
        
        while len(final) < MAX_CONFIGS:
            added_any = False
            for src in sources_order:
                is_sni_ru_src = (src is remaining_ru_sni or src is buckets[0] or src is buckets[2])
                count = 0
                while count < INTERLEAVE_STEP and len(final) < MAX_CONFIGS and src:
                    if is_sni_ru_src and current_ru_sni_total >= MAX_TOTAL_SNI_RU:
                        break
                    config = src.pop(0)
                    if config not in final:
                        final.append(config)
                        count += 1
                        added_any = True
                        if is_sni_ru_src:
                            current_ru_sni_total += 1
            if not added_any:
                break
            
        speed_rating = {r['link']: rank + 1 for rank, r in enumerate(sorted(final, key=lambda x: x['ping']))}
        return [rename_config(r['link'], r['country'], speed_rating[r['link']], r['is_hosting'], r['white_sni'], r.get('exp_tag')) for r in final]
        
    if gh_repo:
        for fn, res in [(FILENAME_VLM, vlm_results), (FILENAME_VLM2, vlm2_results)]:
            output = finalize_list(res, is_vlm2=(fn == FILENAME_VLM2))
            path = f"githubmirror/{fn}"
            content = "\n".join(output)
            try:
                sha = gh_repo.get_contents(path).sha
                gh_repo.update_file(path, f"🚀 {fn} | {len(output)} | {offset}", content, sha)
            except:
                gh_repo.create_file(path, f"🚀 {fn} | {len(output)} | {offset}", content)
    
    print(f"--- 🏁 ГОТОВО за {time.perf_counter() - start_total:.1f}с ---")

if __name__ == "__main__":
    main()
