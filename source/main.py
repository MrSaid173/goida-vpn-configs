import os, re, requests, urllib3, concurrent.futures, ipaddress, base64, json, time, socket
from datetime import datetime
import zoneinfo
from github import Github, Auth

# --- НАСТРОЙКИ ---
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MrSaid173/golden-paths_configs"
FINAL_FILENAME = "vlm"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
EXCLUDE_PROTOCOLS = ("ss://", "trojan://")
MAX_CONFIGS = 150
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

# Глобальный кэш и счетчики
last_geoip_time = 0
subnet_geo_cache = {}

# --- ФУНКЦИИ ПРОВЕРКИ ---

def is_server_alive(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except: return False

def check_is_ru(subnet):
    global last_geoip_time
    if subnet in subnet_geo_cache: return subnet_geo_cache[subnet]
    
    # Rate Limiter для ip-api (45/min)
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
    """Извлекает хост, порт и SNI."""
    try:
        if link.startswith("vmess://"):
            p = link[8:]; p += "=" * ((4 - len(p) % 4) % 4)
            data = json.loads(base64.b64decode(p).decode('utf-8'))
            return data.get('add'), int(data.get('port', 443)), data.get('sni') or data.get('host') or "no-sni"
        host_match = re.search(r'@([^:/?#\s]+):(\d+)', link)
        sni_match = re.search(r'[?&](?:sni|host)=([^&#\s]+)', link)
        if host_match:
            host = host_match.group(1)
            port = int(host_match.group(2))
            sni = sni_match.group(1).lower() if sni_match else "no-sni"
            return host, port, sni
    except: pass
    return None, None, None

# --- ПАРСИНГ ИСТОЧНИКОВ ---

def get_remote_data():
    try:
        resp = session.get(REMOTE_SOURCE_URL, timeout=15)
        resp.raise_for_status()
        code = resp.text
        all_lists = re.findall(r'(\w+)\s*=\s*\[(.*?)\]', code, re.DOTALL | re.IGNORECASE)
        std_src, extra_src, raw_sni_list = [], [], []
        for var_name, content in all_lists:
            items = re.findall(r'["\']([^"\']+)["\']', content)
            if var_name.upper() == "URLS": std_src = items
            elif var_name.upper() == "EXTRA_URLS_FOR_26": extra_src = items
            elif var_name.upper() == "SNI_DOMAINS": raw_sni_list = items
        return extra_src, std_src, raw_sni_list
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
    final_list, seen_hosts = [], set()
    sni_counts, subnet_counts = {}, {}
    ru_count = 0

    def process_pool(urls, use_sni_filter=True):
        nonlocal ru_count
        with concurrent.futures.ThreadPoolExecutor(max_workers=35) as executor:
            # Загружаем все сырые конфиги из пачки URL
            future_to_url = {executor.submit(fetch_raw_configs, u): u for u in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                configs = future.result()
                for config in configs:
                    if len(final_list) >= MAX_CONFIGS: return

                    # 2-3. Фильтр протоколов, текста и SNI (базовый)
                    if config.lower().startswith(EXCLUDE_PROTOCOLS) or "openproxy" in config.lower(): continue
                    
                    host, port, sni = get_config_details(config)
                    if not host or host in seen_hosts: continue
                    
                    # 2 (продолжение). Фильтр по списку разрешенных SNI
                    if use_sni_filter and sni_domains:
                        if not any(d in sni for d in sni_domains): continue

                    # 5. Расширенный фильтр SNI (лимит на одинаковые)
                    if sni_counts.get(sni, 0) >= MAX_PER_SNI: continue

                    # 6. Фильтр по подсетям
                    try: ipaddress.ip_address(host)
                    except: continue
                    subnet = ".".join(host.split(".")[:3])
                    if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue

                    # 7. ПИНГ
                    if not is_server_alive(host, port): continue

                    # 8. GeoIP (Русские vs Зарубежные)
                    is_ru = check_is_ru(subnet)
                    if is_ru:
                        if ru_count >= MAX_RU_CONFIGS: continue
                        ru_count += 1
                    else:
                        # Если это зарубежный, проверяем, не превышен ли общий лимит за вычетом RU
                        if (len(final_list) - ru_count) >= (MAX_CONFIGS - MAX_RU_CONFIGS): continue

                    # Добавление
                    seen_hosts.add(host)
                    sni_counts[sni] = sni_counts.get(sni, 0) + 1
                    subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                    final_list.append(config)
                    print(f"✅ [{'RU' if is_ru else 'INT'}] {host} | SNI: {sni}")

    # Исполнение плана:
    print("🚀 Этап 1: EXTRA_URLS")
    process_pool(extra_urls, use_sni_filter=True)

    if len(final_list) < MAX_CONFIGS:
        print("🚀 Этап 2: STD_URLS")
        process_pool(std_urls, use_sni_filter=True)

    if len(final_list) < MAX_CONFIGS:
        print("🚀 Этап 3: Отмена фильтра по SNI (добор)")
        process_pool(extra_urls + std_urls, use_sni_filter=False)

    # Сохранение (GitHub блок оставить как был)
    actual_count = len(final_list)
    if actual_count > 0:
        data = "\n".join(final_list)
        path = f"githubmirror/{FINAL_FILENAME}"
        try:
            curr = REPO.get_contents(path)
            REPO.update_file(path, f"🚀 Sync | RU:{ru_count} | Total:{actual_count}", data, curr.sha)
            print(f"🏁 Финиш! Собрано {actual_count} (RU: {ru_count})")
        except:
            REPO.create_file(path, f"🆕 Init", data)

if __name__ == "__main__":
    main()
    
