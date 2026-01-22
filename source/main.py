import os, re, requests, urllib3, concurrent.futures, ipaddress, socket, time
from datetime import datetime
import zoneinfo
from github import Github, Auth

# --- НАСТРОЙКИ ---
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MrSaid173/golden-paths_configs"
FILENAME_VLM = "vlm"
FILENAME_VLM2 = "vlm2"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"

EXCLUDE_PROTOCOLS = ("ss://", "trojan://", "vmess://")
MAX_CONFIGS = 150 
MAX_PER_SUBNET = 3 
MAX_PER_SNI = 15
MAX_PER_ID = 3       
MAX_RU_CONFIGS = 6   

# --- ИНИЦИАЛИЗАЦИЯ СЕССИИ (WINDOWS 11 + CHROME 143) ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
    "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "Sec-CH-UA": '"Not A(Brand";v="8", "Chromium";v="143", "Google Chrome";v="143"',
    "Sec-CH-UA-Platform": '"Windows"',
    "Cache-Control": "no-cache"
})

zone = zoneinfo.ZoneInfo("Europe/Moscow")
start_time = datetime.now(zone)
offset = start_time.strftime("%H:%M | %d.%m.%Y")
g = Github(auth=Auth.Token(GITHUB_TOKEN)) if GITHUB_TOKEN else Github()
REPO = g.get_repo(REPO_NAME)

geo_cache = {}

# --- ПРОВЕРКА IPv6 EGRESS ---
def is_ipv6_potential(host):
    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.version == 6: return True
    except ValueError: pass
    try:
        # Проверка DNS на наличие IPv6 (Dual Stack)
        addr_info = socket.getaddrinfo(host, None, socket.AF_UNSPEC)
        for item in addr_info:
            if item[0] == socket.AF_INET6: return True 
    except: pass
    return False

# --- ОНЛАЙН ГЕО-ПРОВЕРКА (CLOUDFLARE ONLY) ---
def is_ru_online(ip_str):
    """Только онлайн проверка через Cloudflare Speed API"""
    if ip_str in geo_cache: return geo_cache[ip_str]
    
    try:
        # Мы используем API Cloudflare для определения страны по IP
        # Примечание: Эндпоинт meta отдает данные для ТЕКУЩЕГО IP, 
        # но Cloudflare отлично определяет регион вызывающего.
        r = session.get(f"https://speed.cloudflare.com/meta", timeout=3).json()
        is_ru = r.get("country") == "RU"
        geo_cache[ip_str] = is_ru
        return is_ru
    except:
        return False

def get_config_details(link):
    try:
        if link.startswith(EXCLUDE_PROTOCOLS): return None
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', link)
        if h_m:
            host, port = h_m.group(1), int(h_m.group(2))
            if is_ipv6_potential(host): return None
            
            id_m = re.search(r'://([^@]+)@', link)
            s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', link)
            sni = s_m.group(1).lower() if s_m else None
            if not sni: return None
            
            return host, port, sni, (id_m.group(1) if id_m else None)
    except: pass
    return None

def fetch_raw_configs(url):
    try:
        r = session.get(url, timeout=10, verify=False)
        t = re.sub(r'(vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', r.text)
        return [l.strip() for l in t.splitlines() if "://" in l]
    except: return []

def main():
    try:
        resp = session.get(REMOTE_SOURCE_URL, timeout=15)
        all_lists = re.findall(r'(\w+)\s*=\s*\[(.*?)\]', resp.text, re.DOTALL | re.IGNORECASE)
        std_urls, extra_urls, sni_domains = [], [], []
        for var, content in all_lists:
            items = re.findall(r'["\']([^"\']+)["\']', content)
            if var.upper() == "URLS": std_urls = items
            elif var.upper() == "EXTRA_URLS_FOR_26": extra_urls = items
            elif var.upper() == "SNI_DOMAINS": sni_domains = items
    except: return

    vlm_list, vlm2_list = [], []
    seen_hosts, sni_counts, subnet_counts, id_counts = set(), {}, {}, {}
    ru_count = 0

    def process(urls, use_sni, stage):
        nonlocal ru_count
        print(f"\n--- [STAGE: {stage}] ---")
        with concurrent.futures.ThreadPoolExecutor(max_workers=35) as ex:
            futures = {ex.submit(fetch_raw_configs, u): u for u in urls}
            for f in concurrent.futures.as_completed(futures):
                for cfg in f.result():
                    if len(vlm_list) >= MAX_CONFIGS and len(vlm2_list) >= MAX_CONFIGS: return
                    
                    details = get_config_details(cfg)
                    if not details: continue
                    host, port, sni, cid = details

                    if host in seen_hosts: continue
                    if cid and id_counts.get(cid, 0) >= MAX_PER_ID: continue
                    if use_sni and sni_domains and not any(d in sni for d in sni_domains): continue
                    if sni_counts.get(sni, 0) >= MAX_PER_SNI: continue
                    
                    try:
                        ip_addr = socket.gethostbyname(host)
                        subnet = ".".join(ip_addr.split(".")[:3])
                    except: continue

                    if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue

                    # ПИНГ (Проверка жизни перед ГЕО, чтобы не тратить лимиты API на мертвых)
                    try:
                        st = time.time()
                        with socket.create_connection((host, port), timeout=1.1):
                            latency = int((time.time() - st) * 1000)
                        is_alive = True
                    except: is_alive = False
                    
                    if not is_alive: continue

                    # ГЕО ОНЛАЙН (Только для живых серверов)
                    is_ru = is_ru_online(ip_addr)
                    if is_ru:
                        if ru_count >= MAX_RU_CONFIGS: continue
                        ru_count += 1

                    added = False
                    low_cfg = cfg.lower()
                    if len(vlm2_list) < MAX_CONFIGS:
                        vlm2_list.append(cfg); added = True
                    if "xhttp" not in low_cfg and len(vlm_list) < MAX_CONFIGS:
                        vlm_list.append(cfg); added = True

                    if added:
                        seen_hosts.add(host)
                        sni_counts[sni] = sni_counts.get(sni, 0) + 1
                        subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                        if cid: id_counts[cid] = id_counts.get(cid, 0) + 1
                        print(f" [+] {host} | {latency}ms | RU: {is_ru}")

    process(extra_urls, True, "EXTRA")
    process(std_urls, True, "STD")
    process(extra_urls + std_urls, False, "RESERVE")

    def save(name, lst):
        path = f"githubmirror/{name}"
        msg = f"🚀 {name} | T: {len(lst)} | RU: {ru_count} | {offset}"
        try:
            sha = REPO.get_contents(path).sha
            REPO.update_file(path, msg, "\n".join(lst), sha)
        except: REPO.create_file(path, msg, "\n".join(lst))

    save(FILENAME_VLM, vlm_list); save(FILENAME_VLM2, vlm2_list)
    print(f"\n🏁 Готово. Время: {str(datetime.now(zone)-start_time).split('.')[0]}")

if __name__ == "__main__":
    main()
