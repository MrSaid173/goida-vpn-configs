import os, re, requests, urllib3, concurrent.futures, ipaddress, base64, json, time, socket
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

# Пути для работы внутри GitHub Actions
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MMDB_PATH = os.path.join(BASE_DIR, "GeoLite2-Country.mmdb")

EXCLUDE_PROTOCOLS = ("ss://", "trojan://", "vmess://")
EXCLUDE_KEYWORDS = ("openproxy", "type=ws")
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

# Кэширование
geo_cache = {} 
last_online_geoip_time = 0

# --- ФУНКЦИИ ГЕОЛОКАЦИИ ---

def update_mmdb():
    """Скачивание и проверка актуальности локальной базы GeoLite2"""
    print("--- [GEO БД] Проверка состояния ---")
    if os.path.exists(MMDB_PATH):
        file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(MMDB_PATH))
        if file_age < timedelta(days=3):
            print(f"✅ База актуальна (возраст: {file_age.days} дн.). Путь: {MMDB_PATH}")
            return
    
    print(f"📥 База устарела или отсутствует. Скачивание с {MMDB_URL}...")
    try:
        r = requests.get(MMDB_URL, timeout=60)
        with open(MMDB_PATH, "wb") as f:
            f.write(r.content)
        print("✅ База GeoLite2 успешно обновлена.")
    except Exception as e:
        print(f"❌ Критическая ошибка при скачивании БД: {e}")

def is_ru_ip(ip_str):
    """Логика: Кэш -> MMDB -> ip-api.com -> Кэш"""
    global last_online_geoip_time
    
    if ip_str in geo_cache: 
        return geo_cache[ip_str]
    
    # 1. Проверка через локальную MMDB
    is_ru = False
    found_in_db = False
    try:
        with maxminddb.open_database(MMDB_PATH) as reader:
            record = reader.get(ip_str)
            if record and 'country' in record:
                is_ru = record['country'].get('iso_code') == 'RU'
                found_in_db = True
    except:
        pass

    if found_in_db:
        geo_cache[ip_str] = is_ru
        return is_ru

    # 2. Fallback: Проверка через ip-api.com, если в БД пусто
    print(f"🌐 {ip_str} не найден в БД. Запрос к ip-api.com...")
    
    # Лимит для бесплатного API (45 зап/мин)
    now = time.time()
    wait = 1.4 - (now - last_online_geoip_time)
    if wait > 0: time.sleep(wait)
    
    try:
        url = f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,isp,org,asname"
        r = session.get(url, timeout=5).json()
        last_online_geoip_time = time.time()
        
        if r.get("status") == "success":
            info = (r.get("isp", "") + " " + r.get("org", "") + " " + r.get("asname", "")).lower()
            is_ru = (r.get("countryCode") == "RU") or any(
                k in info for k in ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota", "vimpelcom", "russia"]
            )
            print(f"   ∟ Ответ API: {r.get('countryCode')} | RU={is_ru}")
            geo_cache[ip_str] = is_ru
            return is_ru
    except Exception as e:
        print(f"   ⚠️ Ошибка API для {ip_str}: {e}")
    
    return False

# --- ФУНКЦИИ ПРОВЕРКИ ---

def is_server_alive(host, port, timeout=1.8):
    """Проверка доступности TCP порта"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except: return False

def get_config_details(link):
    """
    Парсинг конфига. 
    П.3: Бан без SNI. П.5: Бан vmess. П.6: Бан IPv6.
    """
    try:
        if link.startswith("vmess://"): return None, None, None # П.5
        
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', link)
        
        if h_m:
            host = h_m.group(1)
            port = int(h_m.group(2))
            sni = (s_m.group(1).lower() if s_m else None)

            # П.3: Если нет SNI — отсекаем
            if not sni: return None, None, "missing_sni"
            
            # П.6: Проверка на IPv6 (строковая)
            if ":" in host and not host.startswith("["): # Простая проверка на вхождение двоеточия
                if host.count(":") > 1: return None, None, "ipv6"
            try:
                if ipaddress.ip_address(host).version == 6: return None, None, "ipv6"
            except: pass
                
            return host, port, sni
    except: pass
    return None, None, None

def get_remote_data():
    """Сбор источников из репозитория-донора"""
    print("📡 Получение списка источников...")
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
        print(f"✅ Получено: {len(std_src)} осн. источников, {len(extra_src)} доп. источников.")
        return extra_src, std_src, sni_list
    except Exception as e:
        print(f"❌ Ошибка получения источников: {e}")
        return [], [], []

def fetch_raw_configs(url):
    try:
        resp = session.get(url, timeout=15, verify=False)
        text = re.sub(r'(vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', resp.text)
        return [l.strip() for l in text.splitlines() if "://" in l]
    except: return []

# --- ГЛАВНАЯ ЛОГИКА ---

def main():
    update_mmdb()
    extra_urls, std_urls, sni_domains = get_remote_data()
    
    vlm_list, vlm2_list = [], []
    seen_hosts = set()
    sni_counts, subnet_counts = {}, {}
    ru_count = 0

    def process_pool(urls, use_sni_filter=True, stage_name=""):
        nonlocal ru_count
        print(f"\n--- [ЭТАП: {stage_name}] Обработка {len(urls)} ссылок ---")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=35) as executor:
            future_to_url = {executor.submit(fetch_raw_configs, u): u for u in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                configs = future.result()
                for config in configs:
                    if len(vlm_list) >= MAX_CONFIGS and len(vlm2_list) >= MAX_CONFIGS: return

                    low_config = config.lower()
                    
                    # Базовая фильтрация
                    if low_config.startswith(EXCLUDE_PROTOCOLS): continue
                    if any(k in low_config for k in EXCLUDE_KEYWORDS): continue
                    
                    host, port, sni = get_config_details(config)
                    
                    # П.2: Оптимизация (не проверять дважды)
                    if not host or host in seen_hosts: continue
                    
                    # Логирование причин отказа
                    if sni == "missing_sni": continue
                    if sni == "ipv6": continue
                    
                    if use_sni_filter and sni_domains:
                        if not any(d in sni for d in sni_domains): continue

                    if sni_counts.get(sni, 0) >= MAX_PER_SNI: continue
                    
                    try: 
                        ip_addr = socket.gethostbyname(host)
                        if ipaddress.ip_address(ip_addr).version == 6: continue
                        subnet = ".".join(ip_addr.split(".")[:3])
                    except: continue

                    if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue

                    # П.4: Проверка жизни
                    if not is_server_alive(host, port): continue
                    
                    # П.1: Проверка ГЕО (БД + API)
                    is_ru = is_ru_ip(ip_addr)
                    if is_ru:
                        if ru_count >= MAX_RU_CONFIGS: 
                            continue
                        ru_count += 1

                    # Добавление в финальные списки
                    added = False
                    is_xhttp = "xhttp" in low_config
                    if len(vlm2_list) < MAX_CONFIGS:
                        vlm2_list.append(config)
                        added = True
                    if not is_xhttp and len(vlm_list) < MAX_CONFIGS:
                        vlm_list.append(config)
                        added = True

                    if added:
                        seen_hosts.add(host)
                        sni_counts[sni] = sni_counts.get(sni, 0) + 1
                        subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                        print(f" [+] Добавлен: {host} | SNI: {sni} | RU: {is_ru}")

    # Запуск этапов
    process_pool(extra_urls, True, "EXTRA_URLS + SNI_FILTER")
    if len(vlm_list) < MAX_CONFIGS or len(vlm2_list) < MAX_CONFIGS:
        process_pool(std_urls, True, "STD_URLS + SNI_FILTER")
    if len(vlm_list) < MAX_CONFIGS or len(vlm2_list) < MAX_CONFIGS:
        process_pool(extra_urls + std_urls, False, "NO_SNI_FILTER_RESERVE")

    # Сохранение результатов
    def save(filename, lst):
        if not lst: 
            print(f"⚠️ Список {filename} пуст, сохранение отменено.")
            return
        data = "\n".join(lst)
        path = f"githubmirror/{filename}"
        msg = f"🚀 {filename} | Total: {len(lst)} | RU: {ru_count} | {offset}"
        try:
            curr = REPO.get_contents(path)
            REPO.update_file(path, msg, data, curr.sha)
            print(f"✅ {filename} успешно обновлен в репозитории.")
        except: 
            REPO.create_file(path, msg, data)
            print(f"✅ {filename} успешно создан в репозитории.")

    print("\n--- [ФИНАЛИЗАЦИЯ] ---")
    save(FILENAME_VLM, vlm_list)
    save(FILENAME_VLM2, vlm2_list)

if __name__ == "__main__":
    main()
