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

# Словарь для проверки и маппинга названий
COUNTRY_MAP = {
    "RU": {"aliases": ["RUSSIA", "РОССИЯ", "RUS", "🇷🇺"], "full": "Russia", "flag": "🇷🇺"},
    "US": {"aliases": ["USA", "UNITED STATES", "AMERICA", "🇺🇸"], "full": "USA", "flag": "🇺🇸"},
    "DE": {"aliases": ["GERMANY", "ГЕРМАНИЯ", "DEUTSCHLAND", "🇩🇪"], "full": "Germany", "flag": "🇩🇪"},
    "NL": {"aliases": ["NETHERLANDS", "НИДЕРЛАНДЫ", "HOLLAND", "🇳🇱"], "full": "The Netherlands", "flag": "🇳🇱"},
    "GB": {"aliases": ["UNITED KINGDOM", "ENGLAND", "🇬🇧"], "full": "United Kingdom", "flag": "🇬🇧"},
    "TR": {"aliases": ["TURKEY", "ТУРЦИЯ", "TURKIYE", "ТҮРКИЕ", "Türkiye", "🇹🇷"], "full": "Turkey", "flag": "🇹🇷"},
    "KZ": {"aliases": ["KAZAKHSTAN", "КАЗАХСТАН", "🇰🇿"], "full": "Kazakhstan", "flag": "🇰🇿"},
    "FI": {"aliases": ["FINLAND", "ФИНЛЯНДИЯ", "🇫🇮"], "full": "Finland", "flag": "🇫🇮"},
    "PL": {"aliases": ["POLAND", "ПОЛЬША", "🇵🇱"], "full": "Poland", "flag": "🇵🇱"},
}

lock = threading.Lock()
api_semaphore = threading.Semaphore(3)
bad_networks = []
ip_cache = {}

# --- УТИЛИТЫ ---

def rename_config(link, country_code, index):
    """Удаляет старое имя и ставит новое: 🇳🇱 The Netherlands — #1"""
    base_part = link.split('#')[0]
    country_info = COUNTRY_MAP.get(country_code, {"full": country_code, "flag": "🌐"})
    new_name = f"{country_info['flag']} {country_info['full']} — #{index}"
    return f"{base_part}#{requests.utils.quote(new_name)}"

def apply_random_fp(config_link):
    return re.sub(r'fp=[^&?#]+', 'fp=random', config_link)

def remove_udp443(config_link):
    return config_link.replace("-udp443", "")

def get_network_list(file_path, url, name):
    if os.path.exists(file_path) and (datetime.now() - datetime.fromtimestamp(os.path.getmtime(file_path)) < timedelta(days=3)):
        try:
            with open(file_path, "r") as f: 
                return [ipaddress.ip_network(l.strip()) for l in f if l.strip()]
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
                if not is_hosting:
                    bad_keywords = ["cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google", "microsoft", "ovh", "linode", "host"]
                    if any(x in full_info_text for x in bad_keywords):
                        is_hosting = True
                ip_cache[ip_str] = (country, full_info_text, is_hosting)
                return ip_cache[ip_str]
        except: pass
        return None, None, False

def smart_ping(host, port, sni, is_ru=False):
    pings = []
    current_max = MAX_RU_PING if is_ru else MAX_WORLD_PING
    current_min = MIN_RU_PING if is_ru else MIN_WORLD_PING
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
    print(f"--- 🟢 ЗАПУСК [RENAME & SORT MODE] [{offset}] ---")
    
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

    # Списки для хранения объектов: {"link": str, "ping": int, "country": str, "is_priority": bool, "white_sni": bool}
    vlm_results = []
    vlm2_results = []

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
        if not country_code or is_hosting:
            with lock: seen_ips.discard(host)
            return
        
        # Проверка соответствия названия и GeoIP
        name_u = name.upper()
        for code, data in COUNTRY_MAP.items():
            if any(a in name_u for a in data['aliases']) and country_code != code:
                with lock: seen_ips.discard(host)
                return

        is_ru = (country_code == "RU")
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

        ping_res = smart_ping(host, port, sni, is_ru=is_ru)
        
        if ping_res is None:
            with lock:
                seen_ips.discard(host)
                if is_ru: ru_count -= 1
            return

        print(f"[✅ OK] {country_code} | {ping_res}ms | {host}")
        
        final_link = apply_random_fp(config)
        
        with lock:
            # Сохраняем данные для последующей сортировки и переименования
            res_obj = {
                "link": final_link,
                "ping": ping_res,
                "country": country_code,
                "is_priority": is_priority,
                "white_sni": white_sni_only
            }
            vlm2_results.append(res_obj)
            if "xhttp" not in final_link.lower():
                vlm_results.append(res_obj)
            
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
            id_counts[cid] = id_counts.get(cid, 0) + 1
            sni_counts[sni] = sni_counts.get(sni, 0) + 1

    # Запуск валидации
    for p_url, p_sni in [(extra_urls, True), (std_urls, True), (extra_urls, False), (std_urls, False)]:
        process_step_urls = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as gatherer:
            futures = [gatherer.submit(fetch_raw_configs, u) for u in p_url]
            for f in concurrent.futures.as_completed(futures): process_step_urls.extend(f.result())
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as validator:
            for config in process_step_urls:
                validator.submit(validate_one_config, config, p_url == extra_urls, p_sni)

    # --- ФИНАЛЬНАЯ СОРТИРОВКА И ПЕРЕИМЕНОВАНИЕ ---
    def finalize_list(results):
        # 1. Сортируем: сначала Приоритетные (score), внутри них — по Пингу (от быстрого к медленному)
        # Score: Приоритет + WhiteSNI (как в вашем коде)
        results.sort(key=lambda x: (
            (2 if x['white_sni'] else 1) if x['is_priority'] else 0,
            -x['ping'] # Минус, так как reverse=True в общем итоге даст быстрые сверху
        ), reverse=True)
        
        # 2. Обрезаем до лимита
        final_subset = results[:MAX_CONFIGS]
        
        # 3. Переименовываем согласно позиции в финальном списке
        renamed_list = []
        for i, item in enumerate(final_subset, 1):
            new_link = rename_config(item['link'], item['country'], i)
            if results is vlm_results: # Для VLM удаляем udp443
                new_link = remove_udp443(new_link)
            renamed_list.append(new_link)
        return renamed_list

    final_vlm2_links = finalize_list(vlm2_results)
    final_vlm_links = finalize_list(vlm_results)

    # --- ОТПРАВКА В GITHUB ---
    try:
        g = Github(auth=Auth.Token(GITHUB_TOKEN))
        repo = g.get_repo(REPO_NAME)
        for fn, lst in [(FILENAME_VLM, final_vlm_links), (FILENAME_VLM2, final_vlm2_links)]:
            path = f"githubmirror/{fn}"
            msg = f"🚀 {fn} | T: {len(lst)} | RU: {ru_count} | {offset}"
            try:
                sha = repo.get_contents(path).sha
                repo.update_file(path, msg, "\n".join(lst), sha)
            except:
                repo.create_file(path, msg, "\n".join(lst))
    except Exception as e:
        print(f" ❌ GitHub Error: {e}")

    print(f"--- 🏁 ГОТОВО за {time.perf_counter() - start_total:.2f} сек. ---")

if __name__ == "__main__":
    main()
