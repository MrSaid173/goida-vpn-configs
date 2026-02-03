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

# --- УТИЛИТЫ ---

def rename_config(link, country_code, index, is_hosting=False):
    base_part = link.split('#')[0]
    country_info = COUNTRY_MAP.get(country_code, {"full": country_code, "flag": "🌐"})
    
    # Тэг хостинга (добавляем пробел перед ним, если он есть)
    host_tag = " [HOST]" if is_hosting else ""
    
    # Тэг теперь в самом конце после номера
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
    if ip_str in ip_cache: return ip_cache[ip_str]
    with api_semaphore:
        try:
            time.sleep(1.35)
            r = session.get(f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,isp,org,as,asname,hosting", timeout=5).json()
            if r.get("status") == "success":
                isp_data = [str(r.get("isp", "")), str(r.get("org", "")), str(r.get("as", "")), str(r.get("asname", ""))]
                full_info_text = " ".join(isp_data).lower()
                country = r.get("countryCode", "")
                
                is_hosting = r.get("hosting", False)
                bad_keywords = ["cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google", "microsoft", "ovh", "linode", "host", "servers"]
                if not is_hosting:
                    if any(x in full_info_text for x in bad_keywords):
                        is_hosting = True
                        
                ip_cache[ip_str] = (country, full_info_text, is_hosting)
                return ip_cache[ip_str]
        except: pass
        return None, None, False

def smart_ping(host, port, sni, is_ru=False, is_hosting=False):
    pings = []
    
    if is_ru:
        current_min, current_max = MIN_RU_PING, MAX_RU_PING
    else:
        current_min = MIN_WORLD_PING
        if is_hosting:
            calculated_limit = MAX_WORLD_PING / 3.0
            current_max = min(calculated_limit, 150.0)
        else:
            current_max = MAX_WORLD_PING

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        for i in range(3):
            start = time.perf_counter()
            with socket.create_connection((host, port), timeout=1.2) as sock:
                with context.wrap_socket(sock, server_hostname=sni):
                    p = int((time.perf_counter() - start) * 1000)
                    if p > current_max or p < current_min: return None
                    pings.append(p)
            if i < 2: time.sleep(0.15)
        return sum(pings) // len(pings)
    except: return None

def get_config_details(link):
    try:
        name = requests.utils.unquote(link.split("#")[1]) if "#" in link else ""
        clean_link = re.sub(r'[^\x20-\x7E]', '', link).strip()
        id_match = re.search(r'://([^@]+)@', clean_link)
        cid = id_match.group(1) if id_match else None
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', clean_link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', clean_link)
        sni = s_m.group(1).lower() if s_m else ""
        if h_m: return h_m.group(1), int(h_m.group(2)), sni, cid, name
    except: pass
    return None, None, None, None, None

def fetch_raw_configs(url):
    try:
        resp = session.get(url, timeout=10, verify=False).text
        if "://" not in resp[:50] and len(resp) > 64:
            try: resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
            except: pass
        all_links = re.findall(r'(?:vless|ssr|tuic|hysteria|hysteria2)://[^\s]+', resp)
        return [l.strip() for l in all_links if not l.startswith(("ss://", "trojan://"))]
    except: return []

# --- ГЛАВНАЯ ЛОГИКА ---

def main():
    global bad_networks
    start_total = time.perf_counter()
    print(f"--- 🟢 ЗАПУСК [SMART HOSTING FILTER V2 + END TAGS] [{offset}] ---")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as init_executor:
        f_src = init_executor.submit(session.get, REMOTE_SOURCE_URL)
        f_cf = init_executor.submit(get_network_list, os.path.join(os.path.dirname(__file__), "cloudflare_ips.txt"), "https://www.cloudflare.com/ips-v4", "CF")
        f_hz = init_executor.submit(get_network_list, os.path.join(os.path.dirname(__file__), "hetzner_ips.txt"), "https://raw.githubusercontent.com/ipverse/asn-networks/master/networks/AS24940.list", "HZ")
        bad_networks.extend(f_cf.result()); bad_networks.extend(f_hz.result())
        src_text = f_src.result().text

    def get_list_by_name(var_name):
        m = re.search(rf'{var_name}\s*=\s*\[(.*?)\]', src_text, re.S | re.I)
        return re.findall(r'["\']([^"\']+)["\']', m.group(1)) if m else []
        
    extra_urls = get_list_by_name("EXTRA_URLS_FOR_26")
    std_urls = get_list_by_name("URLS")
    sni_domains = set(s.lower() for s in get_list_by_name("SNI_DOMAINS"))

    vlm_results, vlm2_results = [], []
    seen_ips, sni_counts, subnet_counts, id_counts = set(), {}, {}, {}
    ru_count = 0

    def validate_one_config(config, is_priority, white_sni_only):
        nonlocal ru_count
        
        host, port, sni, cid, name = get_config_details(config)
        if not host or not sni: return
        if (sni in sni_domains) != white_sni_only: return

        garbage = ["cloudflare"] 
        if any(x in name.lower() or x in sni for x in garbage): return
        
        with lock:
            if host in seen_ips: return
            seen_ips.add(host)

        try:
            if any(ipaddress.ip_address(host) in net for net in bad_networks):
                with lock: seen_ips.discard(host)
                return
        except:
            with lock: seen_ips.discard(host)
            return

        country_code, isp_info, is_hosting = check_isp_info(host)
        if not country_code:
            with lock: seen_ips.discard(host)
            return
        
        name_u = name.upper()
        is_sni_white = (sni in sni_domains)
        geo_is_ru = (country_code == "RU")
        name_has_ru = any(a in name_u for a in COUNTRY_MAP["RU"]["aliases"])

        if geo_is_ru or name_has_ru:
            if geo_is_ru != name_has_ru:
                with lock: seen_ips.discard(host)
                return
        else:
            if not is_sni_white:
                for code, data in COUNTRY_MAP.items():
                    if code == "RU": continue
                    if any(a in name_u for a in data['aliases']) and country_code != code:
                        with lock: seen_ips.discard(host)
                        return

        is_ru = geo_is_ru
        subnet = ".".join(host.split(".")[:3])
        
        with lock:
            if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET or \
               id_counts.get(cid, 0) >= MAX_PER_ID or \
               sni_counts.get(sni, 0) >= MAX_PER_SNI:
                seen_ips.discard(host)
                return
            if is_ru and ru_count >= MAX_RU_CONFIGS:
                seen_ips.discard(host)
                return
            if is_ru: ru_count += 1

        ping_res = smart_ping(host, port, sni, is_ru=is_ru, is_hosting=is_hosting)
        
        if ping_res is None:
            with lock:
                seen_ips.discard(host)
                if is_ru: ru_count -= 1
            return

        print(f"[✅ OK] {country_code} | {'HOSTING' if is_hosting else 'RESIDENTIAL'} | {ping_res}ms | {host}")
        final_link = apply_random_fp(config)
        
        with lock:
            res_obj = {
                "link": final_link, 
                "ping": ping_res, 
                "country": country_code, 
                "is_priority": is_priority, 
                "white_sni": white_sni_only,
                "is_hosting": is_hosting
            }
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
        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as v:
            for c in step_links: v.submit(validate_one_config, c, p_url == extra_urls, p_sni)

    def finalize_list(results, is_vlm1=False):
        results.sort(key=lambda x: ((2 if x['white_sni'] else 1) if x['is_priority'] else 0, -x['ping']), reverse=True)
        renamed = []
        for i, item in enumerate(results[:MAX_CONFIGS], 1):
            lnk = rename_config(item['link'], item['country'], i, is_hosting=item['is_hosting'])
            if is_vlm1: lnk = remove_udp443(lnk)
            renamed.append(lnk)
        return renamed

    final_v1 = finalize_list(vlm_results, True)
    final_v2 = finalize_list(vlm2_results)

    try:
        g = Github(auth=Auth.Token(GITHUB_TOKEN))
        repo = g.get_repo(REPO_NAME)
        for fn, lst in [(FILENAME_VLM, final_v1), (FILENAME_VLM2, final_v2)]:
            path = f"githubmirror/{fn}"
            msg = f"🚀 {fn} | T: {len(lst)} | RU: {ru_count} | {offset}"
            try:
                sha = repo.get_contents(path).sha
                repo.update_file(path, msg, "\n".join(lst), sha)
            except: repo.create_file(path, msg, "\n".join(lst))
    except Exception as e: print(f" ❌ GitHub Error: {e}")

    print(f"--- 🏁 ГОТОВО за {time.perf_counter() - start_total:.2f} сек. ---")

if __name__ == "__main__":
    main()
