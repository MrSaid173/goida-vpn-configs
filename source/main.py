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
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
MMDB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MMDB_PATH = os.path.join(BASE_DIR, "GeoLite2-Country.mmdb")
CF_IPS_PATH = os.path.join(BASE_DIR, "cloudflare_ips.txt")

MAX_CONFIGS = 150 
MAX_RU_CONFIGS = 6
MAX_PER_SUBNET = 3 
MAX_PER_SNI = 15
MAX_PER_ID = 3

# Твои лимиты по пингу
MIN_RU_PING = 90.0
MAX_ALLOWED_PING = 400.0
SOCKET_TIMEOUT = 0.5  # Порог отсечки (500мс)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
start_time = datetime.now(zone)
offset = start_time.strftime("%H:%M | %d.%m.%Y")

RU_FLAG_EMOJI = "🇷🇺"
COUNTRY_MAP = {
    "RU": ["RUSSIA", "РОССИЯ", "RUS", RU_FLAG_EMOJI],
    "US": ["USA", "UNITED STATES", "AMERICA", "🇺🇸"],
    "DE": ["GERMANY", "ГЕРМАНИЯ", "DEUTSCHLAND", "🇩🇪"],
    "NL": ["NETHERLANDS", "НИДЕРЛАНДЫ", "HOLLAND", "🇳🇱"],
    "GB": ["UNITED KINGDOM", "ENGLAND", "🇬🇧"],
    "TR": ["TURKEY", "ТУРЦИЯ", "TURKIYE", "🇹🇷"],
    "KZ": ["KAZAKHSTAN", "КАЗАХСТАН", "🇰🇿"],
    "AT": ["AUSTRIA", "АВСТРИЯ", "🇦🇹"],
}

def get_cloudflare_networks():
    if os.path.exists(CF_IPS_PATH):
        file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(CF_IPS_PATH))
        if file_age < timedelta(days=3):
            with open(CF_IPS_PATH, "r") as f:
                return [ipaddress.ip_network(l.strip()) for l in f if l.strip()]
    try:
        resp = session.get("https://www.cloudflare.com/ips-v4", timeout=10)
        with open(CF_IPS_PATH, "w") as f: f.write(resp.text)
        return [ipaddress.ip_network(l.strip()) for l in resp.text.splitlines() if l.strip()]
    except: return []

def is_ip_in_networks(ip_str, networks):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in networks:
            if ip_obj in net: return True
    except: pass
    return False

# --- ТРОЙНОЙ ПИНГ С ПАУЗОЙ И ЛИМИТОМ 400МС ---
def get_triple_ping(host, port, sni):
    latencies = []
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        for i in range(3):
            start = time.perf_counter()
            # Таймаут 0.5с для быстрой отсечки безнадежных серверов
            with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=sni) as ssock:
                    latencies.append((time.perf_counter() - start) * 1000)
            
            if i < 2:
                time.sleep(1.1) # Пауза минимум секунда
        
        avg = sum(latencies) / 3
        # Если средний пинг выше 400мс — сервер не подходит
        if avg > MAX_ALLOWED_PING: return None
        return avg
    except:
        return None

def check_ru_isp_online(ip_str):
    try:
        time.sleep(1.35)
        r = session.get(f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,isp,org", timeout=4).json()
        if r.get("status") == "success":
            info = (r.get("isp", "") + " " + r.get("org", "")).lower()
            return (r.get("countryCode") == "RU") or any(k in info for k in ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota"])
    except: pass
    return False

def get_config_details(link):
    try:
        name = requests.utils.unquote(link.split("#")[1]) if "#" in link else ""
        clean_link = re.sub(r'[^\x20-\x7E]', '', link).strip()
        id_match = re.search(r'://([^@]+)@', clean_link)
        cid = id_match.group(1) if id_match else None
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', clean_link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', clean_link)
        if h_m:
            return h_m.group(1), int(h_m.group(2)), (s_m.group(1).lower() if s_m else ""), cid, name
    except: pass
    return None, None, None, None, None

def fetch_raw_configs(url):
    try:
        resp = session.get(url, timeout=12, verify=False).text
        if "://" not in resp[:50] and len(resp) > 64:
            try: resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
            except: pass
        text = re.sub(r'(vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', resp)
        return [l.strip() for l in text.splitlines() if "vless://" in l]
    except: return []

def main():
    if not os.path.exists(MMDB_PATH) or (datetime.now() - datetime.fromtimestamp(os.path.getmtime(MMDB_PATH)) > timedelta(days=3)):
        try:
            r = requests.get(MMDB_URL, timeout=30)
            with open(MMDB_PATH, "wb") as f: f.write(r.content)
        except: pass

    cf_networks = get_cloudflare_networks()
    
    try:
        src = session.get(REMOTE_SOURCE_URL).text
        def get_list(n):
            m = re.search(rf'{n}\s*=\s*\[(.*?)\]', src, re.S)
            return re.findall(r'["\'](https?://[^"\']+)["\']', m.group(1)) if m else []
        extra_urls, std_urls = get_list("EXTRA_URLS_FOR_26"), get_list("URLS")
        sni_match = re.search(r'SNI_DOMAINS\s*=\s*\[(.*?)\]', src, re.S)
        sni_domains = [s.strip(" \"'") for s in sni_match.group(1).split(",")] if sni_match else []
    except: return

    vlm_list, vlm2_list = [], []
    seen_hosts, sni_counts, subnet_counts, id_counts, ru_count = set(), {}, {}, {}, 0

    with maxminddb.open_database(MMDB_PATH) as reader:
        def process_pool(urls, use_sni_filter, stage_name):
            nonlocal ru_count
            print(f"--- [ЭТАП: {stage_name}] ---")
            with concurrent.futures.ThreadPoolExecutor(max_workers=35) as executor:
                f_to_u = {executor.submit(fetch_raw_configs, u): u for u in urls}
                for f in concurrent.futures.as_completed(f_to_u):
                    for config in f.result():
                        if len(vlm2_list) >= MAX_CONFIGS and len(vlm_list) >= MAX_CONFIGS: return
                        
                        host, port, sni, cid, name = get_config_details(config)
                        if not host or host in seen_hosts: continue
                        if use_sni_filter and not any(d in sni for d in sni_domains): continue
                        if sni_counts.get(sni, 0) >= MAX_PER_SNI or id_counts.get(cid, 0) >= MAX_PER_ID: continue
                        
                        try:
                            ip = socket.gethostbyname(host)
                            if is_ip_in_networks(ip, cf_networks): continue

                            subnet = ".".join(ip.split(".")[:3])
                            if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
                            
                            geo = reader.get(ip)
                            ip_country = geo.get('country', {}).get('iso_code', '').upper() if geo else ""
                            
                            name_upper = name.upper()
                            is_ru_by_name = RU_FLAG_EMOJI in name or any(word in name_upper for word in ["RU", "RUSSIA", "РОССИЯ", "RUS"])
                            is_ru_by_ip = (ip_country == 'RU')
                            is_ru_final = is_ru_by_name or is_ru_by_ip

                            # Фильтр RU лимитов
                            if is_ru_final and ru_count >= MAX_RU_CONFIGS: continue

                            # ТРОЙНОЙ ПИНГ
                            avg_latency = get_triple_ping(ip, port, sni)
                            
                            if avg_latency is not None:
                                # ТВОЙ ФИЛЬТР: Для России берем только 90-400мс
                                if is_ru_final:
                                    if avg_latency < MIN_RU_PING: continue 
                                    
                                    if is_ru_by_ip and not is_ru_by_name:
                                        if not check_ru_isp_online(ip): is_ru_final = False
                                        else: ru_count += 1
                                    elif is_ru_by_name: ru_count += 1
                                
                                # Добавление в списки
                                added = False
                                if len(vlm2_list) < MAX_CONFIGS:
                                    vlm2_list.append(config); added = True
                                if "xhttp" not in config.lower() and len(vlm_list) < MAX_CONFIGS:
                                    vlm_list.append(config); added = True
                                
                                if added:
                                    seen_hosts.add(host)
                                    sni_counts[sni] = sni_counts.get(sni, 0) + 1
                                    subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                                    id_counts[cid] = id_counts.get(cid, 0) + 1
                                    print(f" [+] {ip} ({ip_country}) | Ping: {avg_latency:.1f}ms | RU: {ru_count}")
                        except: continue

        process_pool(extra_urls, True, "EXTRA")
        process_pool(std_urls, True, "STD")
        process_pool(extra_urls + std_urls, False, "RESERVE")

    # Сохранение на GitHub
    g = Github(auth=Auth.Token(GITHUB_TOKEN))
    repo = g.get_repo(REPO_NAME)
    for name, lst in [(FILENAME_VLM, vlm_list), (FILENAME_VLM2, vlm2_list)]:
        if not lst: continue
        path = f"githubmirror/{name}"
        msg = f"🚀 {name} | T: {len(lst)} | RU: {ru_count} | {offset}"
        try:
            sha = repo.get_contents(path).sha
            repo.update_file(path, msg, "\n".join(lst), sha)
        except: repo.create_file(path, msg, "\n".join(lst))
    
    print(f"\n🏁 Финиш! RU: {ru_count} | Время: {str(datetime.now(zone)-start_time).split('.')[0]}")

if __name__ == "__main__":
    main()
