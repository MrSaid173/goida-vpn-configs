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
MMDB_PATH = "GeoLite2-Country.mmdb"

EXCLUDE_PROTOCOLS = ("ss://", "trojan://", "vmess://") # Запрет vmess
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

geo_cache = {} # Кэш для результатов геолокации (IP: True/False)

# --- ГЕОЛОКАЦИЯ И БД ---

def update_mmdb():
    """Скачивает или обновляет базу данных GeoLite каждые 3 дня"""
    if os.path.exists(MMDB_PATH):
        file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(MMDB_PATH))
        if file_age < timedelta(days=3):
            return
    print("📥 Обновление базы данных GeoLite...")
    try:
        r = requests.get(MMDB_URL, timeout=30)
        with open(MMDB_PATH, "wb") as f:
            f.write(r.content)
    except Exception as e:
        print(f"❌ Ошибка обновления БД: {e}")

def is_russian_ip(ip_str):
    """Проверяет через локальную БД, является ли IP российским"""
    if ip_str in geo_cache:
        return geo_cache[ip_str]
    
    try:
        with maxminddb.open_database(MMDB_PATH) as reader:
            record = reader.get(ip_str)
            if record and record.get('country'):
                is_ru = record['country'].get('iso_code') == 'RU'
                geo_cache[ip_str] = is_ru
                return is_ru
    except: pass
    return False

# --- ПРОВЕРКИ ---

def check_connectivity(host, port, timeout=2.0):
    """Проверка 'пинг' через попытку установки TCP соединения"""
    # Мы используем TCP проверку, так как HTTP проверку 'через' прокси 
    # невозможно сделать без поднятого клиента V2Ray/Xray в фоне.
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False

def get_config_details(link):
    """Парсит конфиг, извлекает хост, порт и SNI. Отсеивает IPv6 и конфиги без SNI"""
    try:
        # VMess полностью игнорируем согласно п.5
        if link.startswith("vmess://"): return None, None, None

        h_m = re.search(r'@([^:/?#\s]+):(\d+)', link)
        s_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', link)
        
        if h_m:
            host = h_m.group(1)
            port = int(h_m.group(2))
            sni = s_m.group(1).lower() if s_m else None
            
            # 3. Запрет если нет SNI
            if not sni or sni == "no-sni":
                return None, None, None
            
            # 6. Запрет IPv6
            try:
                ip_obj = ipaddress.ip_address(host)
                if ip_obj.version == 6: return None, None, None
            except: 
                # Если это домен, пока пропускаем (разрешим DNS-resolve позже)
                pass
                
            return host, port, sni
    except: pass
    return None, None, None

def fetch_raw_configs(url):
    try:
        resp = session.get(url, timeout=15, verify=False)
        text = re.sub(r'(vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', resp.text)
        return [l.strip() for l in text.splitlines() if "://" in l]
    except: return []

# --- ГЛАВНАЯ ЛОГИКА ---

def main():
    update_mmdb() # Обновляем БД перед стартом
    
    # Получаем списки URL через твой remote_source
    # (Функция get_remote_data остается без изменений из твоего кода)
    from __main__ import get_remote_data 
    extra_urls, std_urls, sni_domains = get_remote_data()
    
    vlm_list, vlm2_list = [], []
    seen_hosts = set()
    sni_counts, subnet_counts = {}, {}
    ru_count = 0

    def process_pool(urls, use_sni_filter=True):
        nonlocal ru_count
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
            future_to_url = {executor.submit(fetch_raw_configs, u): u for u in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                configs = future.result()
                for config in configs:
                    if len(vlm_list) >= MAX_CONFIGS and len(vlm2_list) >= MAX_CONFIGS: return

                    low_config = config.lower()
                    if low_config.startswith(EXCLUDE_PROTOCOLS) or any(k in low_config for k in EXCLUDE_KEYWORDS):
                        continue
                    
                    host, port, sni = get_config_details(config)
                    
                    # 2. Оптимизация: если хост уже видели, не тратим ресурсы
                    if not host or host in seen_hosts: continue
                    
                    if use_sni_filter and sni_domains:
                        if not any(d in sni for d in sni_domains): continue

                    if sni_counts.get(sni, 0) >= MAX_PER_SNI: continue
                    
                    # Проверка подсети (только для IPv4)
                    try:
                        ip_addr = socket.gethostbyname(host)
                        subnet = ".".join(ip_addr.split(".")[:3])
                        if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
                    except: continue

                    # 4. Проверка 'живучести'
                    if not check_connectivity(host, port): continue
                    
                    # 1. Проверка ГЕО через локальную БД
                    is_ru = is_russian_ip(ip_addr)
                    if is_ru:
                        if ru_count >= MAX_RU_CONFIGS: continue
                        ru_count += 1

                    # Добавление в списки
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

    # Запуск этапов фильтрации...
    # (Вызов функций process_pool и save аналогичен твоему коду)

if __name__ == "__main__":
    main()
