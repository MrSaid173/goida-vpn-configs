# mine mine mine mine mine mine mine

import os, re, requests, urllib3, concurrent.futures, ipaddress, base64, json, time, socket, ssl, random
from datetime import datetime, timedelta
import zoneinfo
from github import Github, Auth
import threading
from collections import defaultdict

# --- НАСТРОЙКИ ---
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MrSaid173/golden-paths_configs"
FILENAME_VLM = "vlm"
FILENAME_VLM2 = "vlm2"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
SECONDARY_WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt"

# --- ЛИМИТЫ БРОНИРОВАНИЯ ---
MIN_XHTTP = 1
MAX_XHTTP = 5
MIN_RU_CONFIGS = 5
MAX_RU_CONFIGS = 5
MIN_HOST_CONFIGS = 3  # минимум хостинговых
MAX_HOST_CONFIGS = 15  # максимум хостинговых

INTERLEAVE_STEP = 3
EXCLUDED_SNI_DOMAINS = ["userapi", "splitter.wb.ru"]
BAD_HOSTING_KEYWORDS = ["cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google", "microsoft", "ovh", "linode", "servers", "work", "oracle", "leaseweb", "m247", "akamai", "host", "baykov", "dataforest"]

BANNED_ASNAME_PATTERNS = [
    "-ru", "-ua", "-by", "-kz", "-uz", "-ge", "-am", "-az", "-md", "-tj", "-kg", "-tm",
    "-us", "-ca", "-mx", "-br", "-ar", "-cl", "-co", "-pe", "-ve",
    "-de", "-nl", "-gb", "-uk", "-fr", "-it", "-es", "-pl", "-at", "-ch", "-se", "-no",
    "-fi", "-dk", "-ie", "-pt", "-be", "-cz", "-hu", "-ro", "-bg", "-gr", "-tr", "-ee",
    "-lv", "-lt", "-si", "-sk", "-hr", "-rs", "-me", "-ba", "-al", "-is", "-lu", "-mt",
    "-cn", "-hk", "-sg", "-jp", "-kr", "-in", "-tw", "-vn", "-th", "-my", "-ph", "-id",
    "-ae", "-il", "-sa", "-ir", "-iq", "-jo", "-kw", "-qa", "-om", "-ye",
    "-au", "-nz", "-za", "-ng", "-eg", "-ke", "-ma", "-dz", "-tn"
]

# Настройки Jitter
MAX_JITTER = 50
MAX_JITTER_RATIO = 0.4

# Настройки конфигураций
MAX_CONFIGS = 50
MAX_TOTAL_SNI_RU = MAX_CONFIGS // 2
MAX_TOP_RU_SNI = 5
MAX_PER_COUNTRY = 15
MAX_PER_SUBNET = 3
MAX_PER_ID = 6
MAX_FAILED_PER_SUBNET = 6

# Лимиты на повторение SNI
MAX_SAME_SNI_RU = 1
MAX_SAME_SNI_WORLD = 5

MIN_RU_PING, MAX_RU_PING = 90.0, 410.0
MIN_WORLD_PING, MAX_WORLD_PING = 25.0, 550.0

# Расширенные лимиты для XHTTP
MAX_RU_PING_XHTTP = MAX_RU_PING + 120
MAX_WORLD_PING_XHTTP = MAX_WORLD_PING + 120

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
session.headers.update({'Connection': 'keep-alive'})

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
    "SE": {"aliases": ["SWEDEN", "ШВЕЦИЯ", "🇸🇪"], "full": "Sweden", "flag": "🇸🇪"},
    "UA": {"aliases": ["UKRAINE", "УКРАИНА", "🇺🇦"], "full": "Ukraine", "flag": "🇺🇦"},
    "CA": {"aliases": ["CANADA", "КАНАДА", "🇨🇦"], "full": "Canada", "flag": "🇨🇦"},
    "CH": {"aliases": ["SWITZERLAND", "ШВЕЙЦАРИЯ", "🇨🇭"], "full": "Switzerland", "flag": "🇨🇭"},
    "CZ": {"aliases": ["CZECHIA", "CZECH REPUBLIC", "ЧЕХИЯ", "🇨🇿"], "full": "Czechia", "flag": "🇨🇿"},
    "IT": {"aliases": ["ITALY", "ИТАЛИЯ", "🇮🇹"], "full": "Italy", "flag": "🇮🇹"},
    "EE": {"aliases": ["ESTONIA", "ЭСТОНИЯ", "🇪🇪"], "full": "Estonia", "flag": "🇪🇪"},
    "FR": {"aliases": ["FRANCE", "ФРАНЦИЯ", "🇫🇷"], "full": "France", "flag": "🇫🇷"},
    "SG": {"aliases": ["SINGAPORE", "СИНГАПУР", "🇸🇬"], "full": "Singapore", "flag": "🇸🇬"},
    "BG": {"aliases": ["BULGARIA", "БОЛГАРИЯ", "🇧🇬"], "full": "Bulgaria", "flag": "🇧🇬"},
    "LT": {"aliases": ["LITHUANIA", "ЛИТВА", "🇱🇹"], "full": "Lithuania", "flag": "🇱🇹"},
    "BR": {"aliases": ["BRAZIL", "БРАЗИЛИЯ", "🇧🇷"], "full": "Brazil", "flag": "🇧🇷"},
    "JP": {"aliases": ["JAPAN", "ЯПОНИЯ", "🇯🇵"], "full": "Japan", "flag": "🇯🇵"},
    "IE": {"aliases": ["IRELAND", "ИРЛАНДИЯ", "🇮🇪"], "full": "Ireland", "flag": "🇮🇪"},
    "HK": {"aliases": ["HONG KONG", "ГОНКОНГ", "🇭🇰"], "full": "Hong Kong", "flag": "🇭🇰"},
    "IS": {"aliases": ["ICELAND", "ИСЛАНДИЯ", "🇮🇸"], "full": "Iceland", "flag": "🇮🇸"},
    "AL": {"aliases": ["ALBANIA", "АЛБАНИЯ", "🇦🇱"], "full": "Albania", "flag": "🇦🇱"},
    "CO": {"aliases": ["COLOMBIANA", "КОЛУМБИЯ", "🇨🇴"], "full": "Colombiana", "flag": "🇨🇴"},
    "MD": {"aliases": ["MOLDOVA", "МОЛДОВА", "🇲🇩"], "full": "Moldova", "flag": "🇲🇩"},
    "HU": {"aliases": ["HUNGARY", "ВЕНГРИЯ", "🇭🇺"], "full": "Hungary", "flag": "🇭🇺"},
    "ES": {"aliases": ["SPAIN", "ИСПАНИЯ", "🇪🇸"], "full": "Spain", "flag": "🇪🇸"},
    "IR": {"aliases": ["IRAN", "ИРАН", "🇮🇷"], "full": "Iran", "flag": "🇮🇷"},
    "KR": {"aliases": ["ROK", "KOREA", "ЮЖНАЯ КОРЕЯ", "🇰🇷"], "full": "South Korea", "flag": "🇰🇷"},
    "MY": {"aliases": ["MALAYSIA", "МАЛАЙЗИЯ", "🇲🇾"], "full": "Malaysia", "flag": "🇲🇾"},
    "AE": {"aliases": ["UAE", "UNITED ARAB EMIRATES", "ОАЭ", "🇦🇪"], "full": "UAE", "flag": "🇦🇪"},
    "SK": {"aliases": ["SLOVAKIA", "СЛОВАКИЯ", "🇸🇰"], "full": "Slovakia", "flag": "🇸🇰"},
    "GR": {"aliases": ["GREECE", "ГРЕЦИЯ", "🇬🇷"], "full": "Greece", "flag": "🇬🇷"},
}

# --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ---
lock = threading.Lock()
api_semaphore = threading.Semaphore(3)
stop_event = threading.Event()

# Кэши и счетчики
ip_cache = {}
failed_ips = set()  # Кэш заведомо плохих IP
failed_subnets = defaultdict(int)
seen_ips = set()
subnet_counts = defaultdict(int)
id_counts = defaultdict(int)
country_counts = defaultdict(int)
sni_usage_counts = defaultdict(int)

# Счетчики для vlm/vlm2
ru_vlm_count = 0
ru_vlm2_count = 0
xhttp_count = 0
hosting_count = 0

vlm_results = []
vlm2_results = []

last_api_call = 0

# Статистика для отладки
stats = defaultdict(int)
api_calls_count = 0

def is_valid_ipv4(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except:
        return False


def is_technically_broken(link):
    l = link.lower()
    if "type=" not in l:
        return True
    if "type=http" in l and "type=httpupgrade" not in l:
        return True
    if "type=splithttp" in l:
        return True
    if ":443/?" in l or ":80/?" in l or "/??" in l:
        return True
    if "host=" in l or "packetencoding=" in l or "type=raw" in l:
        return True
    if "vless://" in l:
        match = re.search(r'vless://([a-f0-9\-]{32,36})@', l)
        if not match:
            return True
    if "pbk=" in l:
        if "security=tls" in l or ":80?" in l:
            return True
    if "flow=xtls-rprx-vision" in l and "type=tcp" not in l:
        return True

    s_m = re.search(r'[?&]sni=([^&#\s]*)', l)
    h_m = re.search(r'@([^:/?#\s]+):(\d+)', l)
    if ("security=tls" in l or "security=reality" in l):
        if not s_m:
            return True
        sni = s_m.group(1)
        if is_valid_ipv4(sni):
            return True
    if h_m:
        port = int(h_m.group(2))
        if not (1 <= port <= 65535):
            return True

    return False


def fast_ping(host, port, sni):
    try:
        start = time.perf_counter()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=1.1) as sock:
            with context.wrap_socket(sock, server_hostname=sni if sni else None) as ssock:
                return int((time.perf_counter() - start) * 1000)
    except:
        return None


def full_ping_analysis(host, port, sni, initial_ping):
    pings = [initial_ping]
    max_attempts = 3
    try:
        for _ in range(max_attempts):
            if stop_event.is_set():
                return None
            time.sleep(0.15)
            p = fast_ping(host, port, sni)
            if p:
                pings.append(p)
        if len(pings) < 4:
            return None
        avg = sum(pings) // len(pings)
        jit = sum(abs(p - avg) for p in pings) // len(pings)
        if jit > (avg * MAX_JITTER_RATIO):
            return None
        return avg, jit
    except:
        return None


def get_config_details(link):
    try:
        clean_link = re.sub(r'[^\x20-\x7E]', '', link).strip()
        cid_match = re.search(r'://([^@]+)@', clean_link)
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', clean_link)
        s_m = re.search(r'[?&]sni=([^&#\s]*)', clean_link)
        if h_m and is_valid_ipv4(h_m.group(1)):
            sni = s_m.group(1).lower().split('?')[0].split('&')[0] if s_m else ""
            return h_m.group(1), int(h_m.group(2)), sni, cid_match.group(1) if cid_match else ""
    except:
        pass
    return None, None, None, None


def check_isp_info(ip_str):
    global last_api_call, api_calls_count
    with lock:
        if ip_str in ip_cache:
            return ip_cache[ip_str]
    with api_semaphore:
        try:
            for _ in range(2):
                if stop_event.is_set():
                    return None, False
                with lock:
                    elapsed = time.perf_counter() - last_api_call
                    if elapsed < 1.4:
                        time.sleep(1.4 - elapsed)
                    last_api_call = time.perf_counter()
                    api_calls_count += 1
                resp = session.get(f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,isp,org,as,asname,hosting", timeout=5)
                r = resp.json()
                if r.get("status") == "success":
                    full_info = f"{r.get('isp')} {r.get('org')} {r.get('as')} {r.get('asname')}".lower()
                    is_banned_hosting = any(word in full_info for word in BAD_HOSTING_KEYWORDS)
                    is_banned_pattern = any(pattern.lower() in full_info for pattern in BANNED_ASNAME_PATTERNS)
                    is_banned = is_banned_hosting or is_banned_pattern
                    # ИСПРАВЛЕНО: Возвращаем только 2 значения вместо 3
                    res = (r.get("countryCode"), "BANNED" if is_banned else r.get("hosting", False))
                    with lock:
                        ip_cache[ip_str] = res
                    return res
                break
        except:
            pass
        return None, False


def apply_clean_params(config_link):
    parts = config_link.split("#", 1)
    base = re.sub(r'[&?](?:fp|udp443)=[^&?#]+', '', parts[0])
    sep = "&" if "?" in base else "?"
    base = f"{base}{sep}fp=random"
    base = base.replace("?&", "?").replace("&&", "&").replace("//", "/").replace(":/", "://")
    return f"{base}#{parts[1]}" if len(parts) > 1 else base


def rename_config(link, country_code, index, is_hosting=False, is_white_sni=False):
    country_info = COUNTRY_MAP.get(country_code, {"full": country_code, "flag": "🌐"})
    tags = []
    # ИСПРАВЛЕНО: Используем == вместо is для сравнения
    if is_hosting == True:
        tags.append("HOST")
    if is_white_sni:
        tags.append("SNI-RU")
    tag_str = f" [{'|'.join(tags)}]" if tags else ""
    new_name = f"{country_info['flag']} {country_info['full']} — #{index}{tag_str}"
    return f"{link.split('#')[0]}#{requests.utils.quote(new_name)}"


def fetch_raw_configs(url):
    try:
        resp = session.get(url, timeout=7, verify=False).text
        if "://" not in resp[:50]:
            try:
                resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
            except:
                pass
        return [l.strip() for l in re.findall(r'(?:vless|ssr|tuic|hysteria|hysteria2)://[^\s]+', resp) if not l.startswith(("ss://", "trojan://"))]
    except:
        return []


# ИСПРАВЛЕНО: Передаем ip_cc вместо config
def get_sni_limit(is_white, ip_cc):
    """Определяет лимит использования SNI на основе реальной страны IP"""
    is_ru = (ip_cc == "RU")
    return MAX_SAME_SNI_RU if (is_ru and is_white) else MAX_SAME_SNI_WORLD


def passes_ping_limits(ip_cc, ping, is_xhttp):
    """Проверяет, проходит ли конфиг по лимитам пинга"""
    is_ru = (ip_cc == "RU")
    if is_xhttp:
        max_p = MAX_RU_PING_XHTTP if is_ru else MAX_WORLD_PING_XHTTP
    else:
        max_p = MAX_RU_PING if is_ru else MAX_WORLD_PING
    return ping <= max_p


# ИСПРАВЛЕНО: Полностью переработана логика резервирования
def can_add_hosting(is_hosting):
    """Проверяет, можно ли добавить хостинговый конфиг с упреждающим резервированием"""
    global hosting_count
    
    # ИСПРАВЛЕНО: Используем == вместо is
    if is_hosting == True:
        # Хостинговый конфиг - проверяем не превышен ли максимум
        return hosting_count < MAX_HOST_CONFIGS
    else:
        # НЕ-хостинговый конфиг - проверяем резервирование места
        # Если еще не набрали минимум хостинговых, резервируем место
        if hosting_count < MIN_HOST_CONFIGS:
            total_used = len(vlm_results) + len(vlm2_results)
            # Резервируем место: не позволяем заполнить более чем (2*MAX_CONFIGS - MIN_HOST_CONFIGS)
            max_non_hosting = (MAX_CONFIGS * 2) - MIN_HOST_CONFIGS
            if total_used >= max_non_hosting:
                return False
        return True


def try_add_to_lists(entry):
    """Пытается добавить конфиг в vlm и/или vlm2, возвращает True если добавлен хотя бы куда-то"""
    global ru_vlm_count, ru_vlm2_count, xhttp_count, hosting_count
    
    is_ru = (entry['country'] == 'RU')
    is_xhttp = entry['is_xhttp']
    is_hosting = entry['is_hosting']
    
    added_vlm = False
    added_vlm2 = False
    
    if is_xhttp:
        # XHTTP: только в vlm2
        if is_ru:
            if ru_vlm2_count < MAX_RU_CONFIGS and xhttp_count < MAX_XHTTP and can_add_hosting(is_hosting):
                vlm2_results.append(entry)
                ru_vlm2_count += 1
                xhttp_count += 1
                added_vlm2 = True
        else:
            if xhttp_count < MAX_XHTTP and len(vlm2_results) < MAX_CONFIGS and can_add_hosting(is_hosting):
                vlm2_results.append(entry)
                xhttp_count += 1
                added_vlm2 = True
    else:
        # Обычный конфиг
        # 1. Пробуем добавить в vlm
        if is_ru:
            if ru_vlm_count < MAX_RU_CONFIGS and len(vlm_results) < MAX_CONFIGS and can_add_hosting(is_hosting):
                vlm_results.append(entry)
                ru_vlm_count += 1
                added_vlm = True
        elif len(vlm_results) < MAX_CONFIGS and can_add_hosting(is_hosting):
            vlm_results.append(entry)
            added_vlm = True
        
        # 2. Пробуем добавить в vlm2
        reserved_for_xhttp = max(0, MIN_XHTTP - xhttp_count)
        vlm2_space = MAX_CONFIGS - reserved_for_xhttp
        if is_ru:
            if ru_vlm2_count < MAX_RU_CONFIGS and len(vlm2_results) < vlm2_space and can_add_hosting(is_hosting):
                vlm2_results.append(entry)
                ru_vlm2_count += 1
                added_vlm2 = True
        elif len(vlm2_results) < vlm2_space and can_add_hosting(is_hosting):
            vlm2_results.append(entry)
            added_vlm2 = True
    
    # ИСПРАВЛЕНО: Увеличиваем hosting_count сразу при успешном добавлении
    if added_vlm or added_vlm2:
        if is_hosting == True:
            hosting_count += 1
        return True
    
    return False


def check_completion():
    """Проверяет, достигнуты ли все цели и нужно ли останавливать поиск"""
    vlm_done = (ru_vlm_count >= MIN_RU_CONFIGS and len(vlm_results) >= MAX_CONFIGS)
    vlm2_done = (ru_vlm2_count >= MIN_RU_CONFIGS and xhttp_count >= MIN_XHTTP and len(vlm2_results) >= MAX_CONFIGS)
    
    if vlm_done and vlm2_done:
        stop_event.set()
        return True
    return False


def update_counters(host, sni, subnet, cid, ip_cc):
    """Обновляет все счетчики после добавления конфига"""
    seen_ips.add(host)
    sni_usage_counts[sni] += 1
    subnet_counts[subnet] += 1
    id_counts[cid] += 1
    if ip_cc != "RU":
        country_counts[ip_cc] += 1


def validate(config, is_priority, is_white):
    """Основная функция валидации конфига"""
    # 1. Быстрые проверки без lock
    if stop_event.is_set():
        stats['stopped'] += 1
        return
    
    if is_technically_broken(config):
        stats['broken'] += 1
        return
    
    # ИСПРАВЛЕНО: Убрали неиспользуемую переменную name
    host, port, sni, cid = get_config_details(config)
    if not host or not sni:
        stats['no_details'] += 1
        return
    
    # 2. Проверка кэша неудачных IP
    if host in failed_ips:
        stats['failed_ip_cache'] += 1
        return
    
    is_xhttp = "xhttp" in config.lower()
    
    # ИСПРАВЛЕНО: Сначала получаем ip_cc, потом проверяем лимиты SNI
    # Нужно проверить ISP до lock-блока, чтобы не держать lock во время API запроса
    # Но базовые проверки можем сделать сразу
    
    subnet = ".".join(host.split(".")[:3])
    
    # 3. Lock-блок для быстрых проверок
    with lock:
        if host in seen_ips:
            stats['duplicate_ip'] += 1
            return
        
        if (sni in sni_domains) != is_white:
            stats['sni_mismatch'] += 1
            return
        
        if any(exc in sni for exc in EXCLUDED_SNI_DOMAINS):
            stats['excluded_sni'] += 1
            return
        
        # Проверка лимитов подсети и ID
        if subnet_counts[subnet] >= MAX_PER_SUBNET:
            stats['subnet_limit'] += 1
            return
        
        if id_counts[cid] >= MAX_PER_ID:
            stats['id_limit'] += 1
            return
    
    # 4. Первый пинг (без lock)
    p1 = fast_ping(host, port, sni)
    
    initial_max_p = MAX_WORLD_PING_XHTTP if is_xhttp else MAX_WORLD_PING
    if not p1 or p1 > initial_max_p:
        # ИСПРАВЛЕНО: Штрафуем в одном lock-блоке
        with lock:
            failed_subnets[subnet] += 1
            failed_ips.add(host)
        stats['first_ping_failed'] += 1
        return
    
    # 5. Проверка ISP (без lock)
    # ИСПРАВЛЕНО: Теперь функция возвращает только 2 значения
    ip_cc, ip_h_stat = check_isp_info(host)
    if not ip_cc or ip_h_stat == "BANNED" or stop_event.is_set():
        stats['isp_banned'] += 1
        return
    
    # ИСПРАВЛЕНО: Проверяем лимит SNI ПОСЛЕ получения ip_cc
    with lock:
        sni_limit = get_sni_limit(is_white, ip_cc)
        if sni_usage_counts[sni] >= sni_limit:
            stats['sni_limit'] += 1
            return
    
    # 6. Проверка пинга по стране
    if not passes_ping_limits(ip_cc, p1, is_xhttp):
        stats['ping_limit'] += 1
        return
    
    # 7. Полный анализ пинга (без lock)
    full = full_ping_analysis(host, port, sni, p1)
    if not full or full[1] > MAX_JITTER:
        stats['jitter_failed'] += 1
        return
    
    # 8. Финальное добавление с lock
    with lock:
        # Двойная проверка на случай race condition
        if host in seen_ips:
            stats['race_duplicate'] += 1
            return
        
        # Проверка, не блокирована ли подсеть после полной валидации
        if failed_subnets[subnet] >= MAX_FAILED_PER_SUBNET:
            stats['subnet_banned'] += 1
            return
        
        entry = {
            "link": apply_clean_params(config),
            "ping": full[0],
            "country": ip_cc,
            "is_priority": is_priority,
            "white_sni": is_white,
            "is_hosting": ip_h_stat,
            "is_xhttp": is_xhttp,
        }
        
        # Попытка добавить в списки
        if try_add_to_lists(entry):
            # ИСПРАВЛЕНО: Убрали is_hosting из параметров
            update_counters(host, sni, subnet, cid, ip_cc)
            host_tag = " (X)" if is_xhttp else ""
            print(f"[FOUND{host_tag}] {ip_cc} | {full[0]}ms | {host}", flush=True)
            stats['added'] += 1
            
            # Проверка завершения
            check_completion()
        else:
            stats['not_added'] += 1


def fetch_group_data(urls):
    """Загружает конфиги из списка URL"""
    raw = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(fetch_raw_configs, u) for u in set(urls)]
        for f in concurrent.futures.as_completed(futures):
            raw.extend(f.result())
    unique = list(set(raw))
    random.shuffle(unique)
    return unique


def finalize_list(results, is_vlm2=False):
    """Финализирует список конфигов для vlm или vlm2"""
    all_ru_sni = sorted([r for r in results if r['country'] == 'RU' and r['white_sni']], key=lambda x: x['ping'])
    top_fixed = all_ru_sni[:MAX_TOP_RU_SNI]
    
    xhttp_bucket = []
    if is_vlm2:
        xhttp_bucket = sorted([r for r in results if r.get('is_xhttp')], key=lambda x: x['ping'])
    
    # Разделяем конфиги на RU-SNI и NON-RU-SNI
    ru_sni_configs = []  # Все с [SNI-RU]
    non_ru_sni_configs = []  # Все БЕЗ [SNI-RU]
    
    for r in results:
        if r in top_fixed or r in xhttp_bucket:
            continue
        if r['white_sni']:
            ru_sni_configs.append(r)
        else:
            non_ru_sni_configs.append(r)
    
    # Сортируем по пингу
    ru_sni_configs.sort(key=lambda x: x['ping'])
    non_ru_sni_configs.sort(key=lambda x: x['ping'])
    
    # Начинаем с TOP-5
    final = list(top_fixed)
    current_ru_sni_total = len(top_fixed)
    
    # Чередуем: XHTTP (если vlm2) → NON-RU-SNI → RU-SNI
    while len(final) < MAX_CONFIGS:
        added_any = False
        
        # 1. Добавляем XHTTP (только для vlm2, в начале)
        if is_vlm2 and xhttp_bucket and len(final) == len(top_fixed):
            count = 0
            while count < INTERLEAVE_STEP and len(final) < MAX_CONFIGS and xhttp_bucket:
                config = xhttp_bucket.pop(0)
                if config not in final:
                    final.append(config)
                    count += 1
                    added_any = True
        
        # 2. Добавляем INTERLEAVE_STEP из NON-RU-SNI
        count = 0
        while count < INTERLEAVE_STEP and len(final) < MAX_CONFIGS and non_ru_sni_configs:
            config = non_ru_sni_configs.pop(0)
            if config not in final:
                final.append(config)
                count += 1
                added_any = True
        
        # 3. Добавляем INTERLEAVE_STEP из RU-SNI
        count = 0
        while count < INTERLEAVE_STEP and len(final) < MAX_CONFIGS and ru_sni_configs:
            if current_ru_sni_total >= MAX_TOTAL_SNI_RU:
                break
            config = ru_sni_configs.pop(0)
            if config not in final:
                final.append(config)
                count += 1
                added_any = True
                current_ru_sni_total += 1
        
        if not added_any:
            break
    
    speed_rating = {r['link']: rank + 1 for rank, r in enumerate(sorted(final, key=lambda x: x['ping']))}
    return [rename_config(r['link'], r['country'], speed_rating[r['link']], r['is_hosting'], r['white_sni']) for r in final]


def print_statistics():
    """Выводит статистику обработки"""
    print("\n--- 📊 СТАТИСТИКА ---", flush=True)
    print(f"Добавлено: {stats['added']}", flush=True)
    print(f"Запросов к ip-api: {api_calls_count} (кэш попаданий: {stats['duplicate_ip'] + stats['race_duplicate']})", flush=True)
    print(f"Технически битые: {stats['broken']}", flush=True)
    print(f"Без деталей: {stats['no_details']}", flush=True)
    print(f"Дубликаты IP: {stats['duplicate_ip']}", flush=True)
    print(f"Кэш неудачных IP: {stats['failed_ip_cache']}", flush=True)
    print(f"Первый пинг провален: {stats['first_ping_failed']}", flush=True)
    print(f"ISP забанен: {stats['isp_banned']}", flush=True)
    print(f"Лимит пинга: {stats['ping_limit']}", flush=True)
    print(f"Jitter провален: {stats['jitter_failed']}", flush=True)
    print(f"Лимиты SNI: {stats['sni_limit']}", flush=True)
    print(f"Лимиты подсети: {stats['subnet_limit']}", flush=True)
    print(f"Подсеть забанена: {stats['subnet_banned']}", flush=True)
    print(f"Не добавлено (нет места): {stats['not_added']}", flush=True)
    print(f"\nVLM: {len(vlm_results)} (RU: {ru_vlm_count}, HOST: {sum(1 for r in vlm_results if r['is_hosting'] == True)})", flush=True)
    print(f"VLM2: {len(vlm2_results)} (RU: {ru_vlm2_count}, XHTTP: {xhttp_count}, HOST: {sum(1 for r in vlm2_results if r['is_hosting'] == True)})", flush=True)


def main():
    global sni_domains
    
    start_total = time.perf_counter()
    print(f"--- 🟢 ЗАПУСК [{offset}] ---", flush=True)
    
    sni_domains = set()
    extra_urls, std_urls, gh_repo = [], [], None
    
    try:
        gh_repo = Github(auth=Auth.Token(GITHUB_TOKEN)).get_repo(REPO_NAME)
    except:
        pass
    
    try:
        src_text = session.get(REMOTE_SOURCE_URL, timeout=10).text
        
        def get_list(var):
            m = re.search(rf'{var}\s*=\s*\[(.*?)\]', src_text, re.S | re.I)
            return re.findall(r'["\']([^"\']+)["\']', m.group(1)) if m else []
        
        extra_urls, std_urls = get_list("EXTRA_URLS_FOR_26"), get_list("URLS")
        sni_domains.update(s.lower() for s in get_list("SNI_DOMAINS"))
        
        sec_text = session.get(SECONDARY_WHITELIST_URL, timeout=10).text
        sni_domains.update([l.strip().lower() for l in sec_text.splitlines() if l.strip()])
    except:
        pass
    
    print(f"Загружено SNI доменов: {len(sni_domains)}", flush=True)
    print(f"Extra URLs: {len(extra_urls)}, Standard URLs: {len(std_urls)}", flush=True)
    
    # Загрузка конфигов
    raw_extra, raw_std = fetch_group_data(extra_urls), fetch_group_data(std_urls)
    print(f"Уникальных конфигов: Extra={len(raw_extra)}, Std={len(raw_std)}", flush=True)
    
    # Порядок проверки
    check_order = [
        (raw_extra, True, True),
        (raw_std, False, True),
        (raw_extra, True, False),
        (raw_std, False, False)
    ]
    
    for group, priority, white in check_order:
        if stop_event.is_set():
            break
        workers = min(len(group), 40) if group else 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as v:
            for c in group:
                if stop_event.is_set():
                    break
                v.submit(validate, c, priority, white)
    
    # Статистика
    print_statistics()
    
    # Финализация и загрузка в GitHub
    if gh_repo:
        for fn, res in [(FILENAME_VLM, vlm_results), (FILENAME_VLM2, vlm2_results)]:
            output = finalize_list(res, is_vlm2=(fn == FILENAME_VLM2))
            path, content = f"githubmirror/{fn}", "\n".join(output)
            try:
                sha = gh_repo.get_contents(path).sha
                gh_repo.update_file(path, f"🚀 {fn} | {len(output)} | {offset}", content, sha)
                print(f"✅ Обновлен {fn}: {len(output)} конфигов", flush=True)
            except:
                gh_repo.create_file(path, f"🚀 {fn} | {len(output)} | {offset}", content)
                print(f"✅ Создан {fn}: {len(output)} конфигов", flush=True)
    
    print(f"--- 🏁 ГОТОВО за {time.perf_counter() - start_total:.1f}с ---")


if __name__ == "__main__":
    main()
