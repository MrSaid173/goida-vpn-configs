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

MAX_CONFIGS = 100 
MAX_RU_CONFIGS = 6
MAX_PER_SUBNET = 3 
MAX_PER_SNI = 15
MAX_PER_ID = 6
MAX_FAILED_PER_SUBNET = 5 

MIN_RU_PING, MAX_RU_PING = 90.0, 460.0
MIN_WORLD_PING, MAX_WORLD_PING = 10.0, 430.0

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
}

lock = threading.Lock()
api_semaphore = threading.Semaphore(3)
bad_networks = []
ip_cache = {}
failed_subnets = {} 
last_api_call = 0

# --- УТИЛИТЫ ---

def rename_config(link, country_code, index, is_hosting=False):
    base_part = link.split('#')[0]
    country_info = COUNTRY_MAP.get(country_code, {"full": country_code, "flag": "🌐"})
    host_tag = " [HOST]" if is_hosting else ""
    new_name = f"{country_info['flag']} {country_info['full']} — #{index}{host_tag}"
    return f"{base_part}#{requests.utils.quote(new_name)}"

def apply_random_fp(config_link):
    return re.sub(r'fp=[^&?#]+', 'fp=random', config_link)

def remove_udp443(config_link):
    return config_link.replace("-udp443", "")

def get_network_list(file_path, url, name):
    if os.path.exists(file_path) and (datetime.now() - datetime.fromtimestamp(os.path.getmtime(file_path)) < timedelta(days=3)):
        try:
            with open(file_path, "r") as f: return [ipaddress.ip_network(l.strip()) for l in f if l.strip()]
        except: pass
    try:
        resp = session.get(url, timeout=10)
        found_ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?', resp.text)
        if found_ips:
            with open(file_path, "w") as f: f.write("\n".join(found_ips))
            return [ipaddress.ip_network(ip) for ip in found_ips]
    except: pass
    return []

def check_isp_info(ip_str):
    global last_api_call
    if ip_str in ip_cache: return ip_cache[ip_str]
    with api_semaphore:
        try:
            with lock:
                elapsed = time.perf_counter() - last_api_call
                if elapsed < 1.1: time.sleep(1.1 - elapsed)
                last_api_call = time.perf_counter()
            r = session.get(f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,isp,org,as,asname,hosting", timeout=4).json()
            if r.get("status") == "success":
                isp_data = [str(r.get(k, "")) for k in ["isp", "org", "as", "asname"]]
                full_info_text = " ".join(isp_data).lower()
                country = r.get("countryCode", "")
                is_hosting = r.get("hosting", False)
                bad_keywords = ["cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google", "microsoft", "ovh", "linode", "host", "servers"]
                if not is_hosting: is_hosting = any(x in full_info_text for x in bad_keywords)
                res = (country, full_info_text, is_hosting)
                with lock: ip_cache[ip_str] = res
                return res
        except: pass
        return None, None, False

def smart_ping(host, port, sni, is_ru=False, is_hosting=False):
    pings = []
    c_min = MIN_RU_PING if is_ru else MIN_WORLD_PING
    c_max = min(MAX_WORLD_PING / 3.0, 150.0) if (not is_ru and is_hosting) else (MAX_RU_PING if is_ru else MAX_WORLD_PING)

    try:
        context = ssl.create_default_context()
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        for i in range(2):
            start = time.perf_counter()
            with socket.create_connection((host, port), timeout=1.0) as sock:
                with context.wrap_socket(sock, server_hostname=sni):
                    p = int((time.perf_counter() - start) * 1000)
                    if p > c_max or p < c_min: return None
                    pings.append(p)
            if i < 1: time.sleep(0.1)
        return sum(pings) // len(pings)
    except: return None

def get_config_details(link):
    try:
        name = requests.utils.unquote(link.split("#")[1]) if "#" in link else ""
        clean_link = re.sub(r'[^\x20-\x7E]', '', link).strip()
        cid = re.search(r'://([^@]+)@', clean_link).group(1)
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', clean_link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', clean_link)
        sni = s_m.group(1).lower() if s_m else ""
        if h_m: return h_m.group(1), int(h_m.group(2)), sni, cid, name
    except: pass
    return None, None, None, None, None

def fetch_raw_configs(url):
    try:
        resp = session.get(url, timeout=8, verify=False).text
        if "://" not in resp[:50]:
            try: resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
            except: pass
        return [l.strip() for l in re.findall(r'(?:vless|ssr|tuic|hysteria|hysteria2)://[^\s]+', resp) if not l.startswith(("ss://", "trojan://"))]
    except: return []

# --- ГЛАВНАЯ ЛОГИКА ---

def main():
    global bad_networks
    start_total = time.perf_counter()
    print(f"--- 🟢 ЗАПУСК [STRICT LIMITS MODE] [{offset}] ---", flush=True)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as init_executor:
        f_src = init_executor.submit(session.get, REMOTE_SOURCE_URL)
        f_cf = init_executor.submit(get_network_list, os.path.join(os.path.dirname(__file__), "cloudflare_ips.txt"), "https://www.cloudflare.com/ips-v4", "CF")
        f_hz = init_executor.submit(get_network_list, os.path.join(os.path.dirname(__file__), "hetzner_ips.txt"), "https://raw.githubusercontent.com/ipverse/asn-networks/master/networks/AS24940.list", "HZ")
        bad_networks.extend(f_cf.result() or []); bad_networks.extend(f_hz.result() or [])
        src_text = f_src.result().text

    def get_list_by_name(var_name):
        m = re.search(rf'{var_name}\s*=\s*\[(.*?)\]', src_text, re.S | re.I)
        return re.findall(r'["\']([^"\']+)["\']', m.group(1)) if m else []
        
    extra_urls, std_urls = get_list_by_name("EXTRA_URLS_FOR_26"), get_list_by_name("URLS")
    sni_domains = set(s.lower() for s in get_list_by_name("SNI_DOMAINS"))

    vlm_results, vlm2_results = [], []
    seen_ips, sni_counts, subnet_counts, id_counts = set(), {}, {}, {}
    ru_count = 0

    def validate_one_config(config, is_priority, white_sni_only):
        nonlocal ru_count
        host, port, sni, cid, name = get_config_details(config)
        if not host or not sni or (sni in sni_domains) != white_sni_only: return
        if "cloudflare" in name.lower() or "cloudflare" in sni: return
        
        subnet = ".".join(host.split(".")[:3])

        # 1. ПРЕДВАРИТЕЛЬНАЯ ПРОВЕРКА ЛИМИТОВ
        with lock:
            if failed_subnets.get(subnet, 0) >= MAX_FAILED_PER_SUBNET: return 
            if host in seen_ips: return
            if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: return
            if id_counts.get(cid, 0) >= MAX_PER_ID: return
            if sni_counts.get(sni, 0) >= MAX_PER_SNI: return
            seen_ips.add(host)

        # 2. GEO / ISP
        country_code, isp_info, is_hosting = check_isp_info(host)
        if not country_code: return
        
        name_u, is_ru = name.upper(), (country_code == "RU")
        if is_ru != any(a in name_u for a in COUNTRY_MAP["RU"]["aliases"]): return

        # 3. БРОНИРОВАНИЕ МЕСТА ДЛЯ RU (До пинга)
        if is_ru:
            with lock:
                if ru_count >= MAX_RU_CONFIGS: return
                ru_count += 1

        # 4. ПИНГ
        ping_res = smart_ping(host, port, sni, is_ru=is_ru, is_hosting=is_hosting)
        
        if ping_res is None:
            with lock:
                failed_subnets[subnet] = failed_subnets.get(subnet, 0) + 1
                if is_ru: ru_count -= 1 # ОСВОБОЖДАЕМ МЕСТО, если пинг не прошел
            return

        # 5. ФИНАЛЬНАЯ ЗАПИСЬ
        print(f"[✅ OK] {country_code} | {'HOST' if is_hosting else 'RES'} | {ping_res}ms | {host}", flush=True)
        final_link = apply_random_fp(config)
        
        with lock:
            # Повторная проверка подсетей/лимитов на случай, если за время пинга они заполнились
            if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET:
                if is_ru: ru_count -= 1
                return 

            res_obj = {"link": final_link, "ping": ping_res, "country": country_code, "is_priority": is_priority, "white_sni": white_sni_only, "is_hosting": is_hosting}
            vlm2_results.append(res_obj)
            if "xhttp" not in final_link.lower(): vlm_results.append(res_obj)
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
            id_counts[cid] = id_counts.get(cid, 0) + 1
            sni_counts[sni] = sni_counts.get(sni, 0) + 1

    for p_url, p_sni in [(extra_urls, True), (std_urls, True), (extra_urls, False), (std_urls, False)]:
        step_links = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as g:
            f = [g.submit(fetch_raw_configs, u) for u in p_url]
            for fut in concurrent.futures.as_completed(f): step_links.extend(fut.result())
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as v:
            for c in step_links: v.submit(validate_one_config, c, p_url == extra_urls, p_sni)

    def finalize_list(results, is_vlm1=False):
        results.sort(key=lambda x: ((2 if x['white_sni'] else 1) if x['is_priority'] else 0, -x['ping']), reverse=True)
        return [remove_udp443(rename_config(r['link'], r['country'], i, r['is_hosting'])) if is_vlm1 else rename_config(r['link'], r['country'], i, r['is_hosting']) for i, r in enumerate(results[:MAX_CONFIGS], 1)]

    f_v1, f_v2 = finalize_list(vlm_results, True), finalize_list(vlm2_results)

    try:
        repo = Github(auth=Auth.Token(GITHUB_TOKEN)).get_repo(REPO_NAME)
        for fn, lst in [(FILENAME_VLM, f_v1), (FILENAME_VLM2, f_v2)]:
            path, content = f"githubmirror/{fn}", "\n".join(lst)
            msg = f"🚀 {fn} | T: {len(lst)} | RU: {ru_count} | {offset}"
            try: repo.update_file(path, msg, content, repo.get_contents(path).sha)
            except: repo.create_file(path, msg, content)
    except Exception as e: print(f" ❌ GitHub Error: {e}", flush=True)
    print(f"--- 🏁 ГОТОВО за {time.perf_counter() - start_total:.2f} сек. ---", flush=True)

if __name__ == "__main__":
    main()
