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

# Параметры пинга для RU
MIN_RU_PING = 90.0
MAX_RU_PING = 400.0
SOCKET_TIMEOUT = 0.5 # 500мс на попытку коннекта

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
start_time = datetime.now(zone)
offset = start_time.strftime("%H:%M | %d.%m.%Y")

RU_FLAG_EMOJI = "🇷🇺"

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

def smart_ping(host, port, sni):
    """Быстрая проверка 'жив/мертв' для иностранных серверов"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=1.1) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                return True
    except: return False

def get_online_info(ip_str):
    """Онлайн проверка провайдера и Cloudflare для RU-кандидатов"""
    try:
        time.sleep(1.35)
        r = session.get(f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,isp,org", timeout=4).json()
        if r.get("status") == "success":
            isp_info = (r.get("isp", "") + " " + r.get("org", "")).lower()
            is_cf = "cloudflare" in isp_info
            is_ru = (r.get("countryCode") == "RU") or any(k in isp_info for k in ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota"])
            return is_ru, is_cf
    except: pass
    return False, False

def get_triple_ping(host, port, sni):
    """Замер пинга. Если хотя бы 1 из 3 успешен — сервер рабочий."""
    latencies = []
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    for i in range(3):
        try:
            start = time.perf_counter()
            with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=sni) as ssock:
                    latencies.append((time.perf_counter() - start) * 1000)
        except:
            pass # Игнорируем ошибку одной попытки
        
        if i < 2: 
            time.sleep(1.1) 
    
    # Если есть хотя бы один успешный замер
    if latencies:
        return sum(latencies) / len(latencies)
    return None

def get_config_details(link):
    try:
        name = requests.utils.unquote(link.split("#")[1]) if "#" in link else ""
        clean_link = re.sub(r'[^\x20-\x7E]', '', link).strip()
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', clean_link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', clean_link)
        id_m = re.search(r'://([^@]+)@', clean_link)
        if h_m: return h_m.group(1), int(h_m.group(2)), (s_m.group(1).lower() if s_m else ""), (id_m.group(1) if id_m else None), name
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
    if not os.path.exists(MMDB_PATH):
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
        urls = get_list("EXTRA_URLS_FOR_26") + get_list("URLS")
    except: return

    vlm_list, vlm2_list = [], []
    seen_hosts, subnet_counts, ru_count = set(), {}, 0

    with maxminddb.open_database(MMDB_PATH) as reader:
        print(f"--- [ЗАПУСК С ОПТИМИЗИРОВАННЫМ ПИНГОМ] ---")
        with concurrent.futures.ThreadPoolExecutor(max_workers=35) as executor:
            f_to_u = {executor.submit(fetch_raw_configs, u): u for u in urls}
            for f in concurrent.futures.as_completed(f_to_u):
                for config in f.result():
                    if len(vlm_list) >= MAX_CONFIGS: break
                    host, port, sni, cid, name = get_config_details(config)
                    if not host or host in seen_hosts: continue
                    
                    try:
                        ip = socket.gethostbyname(host)
                        if is_ip_in_networks(ip, cf_networks): continue

                        geo = reader.get(ip)
                        ip_country = geo.get('country', {}).get('iso_code', '').upper() if geo else ""
                        is_ru_candidate = (ip_country == 'RU') or (RU_FLAG_EMOJI in name)

                        if is_ru_candidate:
                            if ru_count >= MAX_RU_CONFIGS: continue
                            
                            is_ru_real, is_cf_online = get_online_info(ip)
                            if is_cf_online or not is_ru_real: continue
                            
                            # ГИБКИЙ ПИНГ: берем, если хоть раз ответил
                            avg_p = get_triple_ping(ip, port, sni)
                            if avg_p is None or avg_p < MIN_RU_PING or avg_p > MAX_RU_PING:
                                continue
                            ru_count += 1
                        else:
                            if not smart_ping(ip, port, sni): continue

                        subnet = ".".join(ip.split(".")[:3])
                        if subnet_counts.get(subnet, 0) < MAX_PER_SUBNET:
                            vlm_list.append(config)
                            vlm2_list.append(config)
                            seen_hosts.add(host)
                            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                            
                            log_status = f"{avg_p:.1f}ms" if is_ru_candidate else "Live"
                            print(f" [+] {ip} ({ip_country}) | Ping: {log_status} | RU: {ru_count}")
                    except: continue

    # Сохранение на GitHub
    g = Github(auth=Auth.Token(GITHUB_TOKEN))
    repo = g.get_repo(REPO_NAME)
    for fname, lst in [(FILENAME_VLM, vlm_list), (FILENAME_VLM2, vlm2_list)]:
        if not lst: continue
        path = f"githubmirror/{fname}"
        msg = f"🚀 {fname} | T: {len(lst)} | RU: {ru_count} | {offset}"
        try:
            sha = repo.get_contents(path).sha
            repo.update_file(path, msg, "\n".join(lst), sha)
        except: repo.create_file(path, msg, "\n".join(lst))
    
    print(f"\n🏁 Финиш! RU: {ru_count}")

if __name__ == "__main__":
    main()
                            
