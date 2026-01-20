import os, re, requests, urllib3, concurrent.futures, ipaddress, base64, json, time, socket
from datetime import datetime
import zoneinfo
from github import Github, Auth

# --- НАСТРОЙКИ ---
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MrSaid173/golden-paths_configs"
FILENAME_VLM = "vlm"
FILENAME_VLM2 = "vlm2"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
EXCLUDE_PROTOCOLS = ("ss://", "trojan://")
EXCLUDE_KEYWORDS = ("openproxy", "type=ws")
MAX_CONFIGS = 150 # Цель для каждого файла
MAX_PER_SUBNET = 3 
MAX_PER_SNI = 5
MAX_RU_CONFIGS = 5

# --- ИНИЦИАЛИЗАЦИЯ ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")
g = Github(auth=Auth.Token(GITHUB_TOKEN)) if GITHUB_TOKEN else Github()
REPO = g.get_repo(REPO_NAME)

last_geoip_time = 0
subnet_geo_cache = {}

# --- ФУНКЦИИ ---

def is_server_alive(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except: return False

def check_is_ru(subnet):
    global last_geoip_time
    if subnet in subnet_geo_cache: return subnet_geo_cache[subnet]
    now = time.time()
    wait = 1.35 - (now - last_geoip_time)
    if wait > 0: time.sleep(wait)
    try:
        url = f"http://ip-api.com/json/{subnet}.1?fields=status,countryCode,isp,org,asname"
        r = session.get(url, timeout=5).json()
        last_geoip_time = time.time()
        if r.get("status") == "success":
            info = (r.get("isp", "") + " " + r.get("org", "") + " " + r.get("asname", "")).lower()
            is_ru = (r.get("countryCode") == "RU") or any(k in info for k in ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota", "vimpelcom", "russia"])
            subnet_geo_cache[subnet] = is_ru
            return is_ru
    except: pass
    return False

def get_config_details(link):
    try:
        if link.startswith("vmess://"):
            p = link[8:]; p += "=" * ((4 - len(p) % 4) % 4)
            data = json.loads(base64.b64decode(p).decode('utf-8'))
            return data.get('add'), int(data.get('port', 443)), (data.get('sni') or data.get('host') or "no-sni").lower()
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', link)
        if h_m:
            return h_m.group(1), int(h_m.group(2)), (s_m.group(1).lower() if s_m else "no-sni")
    except: pass
    return None, None, None

def get_remote_data():
    try:
        resp = session.get(REMOTE_SOURCE_URL, timeout=15)
        code = resp.text
        all_lists = re.findall(r'(\w+)\s*=\s*\[(.*?)\]', code, re.DOTALL | re.IGNORECASE)
        std_src, extra_src, sni_list = [], [], []
        for var, content in all_lists:
            items = re.findall(r'["\']([^"\']+)["\']', content)
            if var.upper() == "URLS": std_src = items
            elif var.upper() == "EXTRA_URLS_FOR_26": extra_src = items
            elif var.upper() == "SNI_DOMAINS": sni_list = items
        return extra_src, std_src, sni_list
    except: return [], [], []

def fetch_raw_configs(url):
    try:
        resp = session.get(url, timeout=15, verify=False)
        text = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', resp.text)
        return [l.strip() for l in text.splitlines() if "://" in l]
    except: return []

# --- ГЛАВНАЯ ЛОГИКА ---

def main():
    extra_urls, std_urls, sni_domains = get_remote_data()
    vlm_list, vlm2_list = [], []
    seen_hosts = set()
    # Счетчики общие, чтобы соблюдать MAX_PER_SNI и т.д.
    sni_counts, subnet_counts = {}, {}
    ru_count = 0

    def process_pool(urls, use_sni_filter=True):
        nonlocal ru_count
        with concurrent.futures.ThreadPoolExecutor(max_workers=35) as executor:
            future_to_url = {executor.submit(fetch_raw_configs, u): u for u in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                configs = future.result()
                for config in configs:
                    # Останавливаемся, только когда ОБА файла полные
                    if len(vlm_list) >= MAX_CONFIGS and len(vlm2_list) >= MAX_CONFIGS: return

                    low_config = config.lower()
                    if low_config.startswith(EXCLUDE_PROTOCOLS) or any(k in low_config for k in EXCLUDE_KEYWORDS):
                        continue
                    
                    host, port, sni = get_config_details(config)
                    if not host or host in seen_hosts: continue
                    
                    if use_sni_filter and sni_domains:
                        if not any(d in sni for d in sni_domains): continue

                    # Лимиты на SNI и подсети
                    if sni_counts.get(sni, 0) >= MAX_PER_SNI: continue
                    try: ipaddress.ip_address(host)
                    except: continue
                    subnet = ".".join(host.split(".")[:3])
                    if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue

                    # Пинг и страна
                    if not is_server_alive(host, port): continue
                    is_ru = check_is_ru(subnet)
                    
                    if is_ru:
                        if ru_count >= MAX_RU_CONFIGS: continue
                        ru_count += 1

                    # ОПРЕДЕЛЯЕМ СУДЬБУ КОНФИГА
                    added = False
                    is_xhttp = "xhttp" in low_config

                    # Попытка добавить в vlm2 (всегда, если не xhttp или если xhttp разрешен)
                    if len(vlm2_list) < MAX_CONFIGS:
                        vlm2_list.append(config)
                        added = True
                    
                    # Попытка добавить в vlm (только если НЕ xhttp)
                    if not is_xhttp and len(vlm_list) < MAX_CONFIGS:
                        vlm_list.append(config)
                        added = True

                    if added:
                        seen_hosts.add(host)
                        sni_counts[sni] = sni_counts.get(sni, 0) + 1
                        subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                        print(f"✅ Добавлен {host} (vlm:{len(vlm_list)}, vlm2:{len(vlm2_list)})")

    # Исполнение этапов
    process_pool(extra_urls, True)
    if len(vlm_list) < MAX_CONFIGS or len(vlm2_list) < MAX_CONFIGS:
        process_pool(std_urls, True)
    if len(vlm_list) < MAX_CONFIGS or len(vlm2_list) < MAX_CONFIGS:
        process_pool(extra_urls + std_urls, False)

    # Сохранение
    def save(filename, lst):
        if not lst: return
        data = "\n".join(lst)
        path = f"githubmirror/{filename}"
        msg = f"🚀 {filename} | Total: {len(lst)} | RU: {ru_count} | {offset}"
        try:
            curr = REPO.get_contents(path)
            REPO.update_file(path, msg, data, curr.sha)
        except: REPO.create_file(path, msg, data)
        print(f"🏁 {filename} сохранен ({len(lst)} шт.)")

    save(FILENAME_VLM, vlm_list)
    save(FILENAME_VLM2, vlm2_list)

if __name__ == "__main__":
    main()
    
