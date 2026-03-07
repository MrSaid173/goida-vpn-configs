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
MIN_HOST_CONFIGS = 3
MAX_HOST_CONFIGS = 13

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
MAX_JITTER = 80
MAX_JITTER_RATIO = 0.4

# Настройки конфигураций
MAX_CONFIGS = 50
MAX_TOTAL_SNI_RU = MAX_CONFIGS // 2
MAX_TOP_RU_SNI = 5

MAX_PER_SUBNET = 3
MAX_PER_SUBNET16_RU_SNI = 1
MAX_PER_SUBNET16_NONRU_SNI = 7
MAX_PER_SUBNET16_OTHERS = 10

MAX_PER_ID = 6
MAX_FAILED_PER_SUBNET = 6

# Лимиты на повторение SNI
MAX_SAME_SNI_RU_RU = 3  # RU IP + white SNI
MAX_SAME_SNI_RU = 8     # Не-RU IP + white SNI
MAX_SAME_SNI_WORLD = 5  # Любой IP + не-white SNI

MIN_RU_PING, MAX_RU_PING = 100.0, 500.0
MIN_WORLD_PING, MAX_WORLD_PING = 25.0, 650.0

# Расширенные лимиты для XHTTP
MAX_RU_PING_XHTTP = MAX_RU_PING + 120
MAX_WORLD_PING_XHTTP = MAX_WORLD_PING + 120

# --- НАСТРОЙКИ RU-ПРОВЕРКИ ---
ANTIFILTER_URLS = [
    "https://antifilter.download/list/subnet.lst",
    "https://antifilter.download/list/allyouneed.lst",
]

# --- НАСТРОЙКИ XRAY-ТЕСТА ---
XRAY_BINARY = os.environ.get("XRAY_BINARY", "/tmp/xray/xray")
XRAY_TEST_URL = "https://www.gstatic.com/generate_204"
XRAY_TIMEOUT = 8          # секунд на весь тест одного конфига
XRAY_STARTUP_WAIT = 1.5   # секунд ждём пока xray поднимется
XRAY_MAX_PARALLEL = 6     # максимум одновременных xray-процессов
XRAY_PORT_BASE = 10000    # стартовый порт для SOCKS5, каждый тред берёт свой


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
failed_ips = set()
failed_subnets = defaultdict(int)
seen_ips = set()
subnet_counts = defaultdict(int)
subnet16_counts = defaultdict(lambda: defaultdict(int))
id_counts = defaultdict(int)
sni_usage_counts = defaultdict(int)

# Счетчики для vlm/vlm2
ru_vlm_count = 0
ru_vlm2_count = 0
xhttp_count = 0

vlm_results = []
vlm2_results = []

last_api_call = 0

# Статистика для отладки
stats = defaultdict(int)
api_calls_count = 0

# --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ДЛЯ RU-ПРОВЕРКИ ---
blocked_networks = []       # список IPv4Network из antifilter
_blocked_cache = {}
_blocked_cache_lock = threading.Lock()

# --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ДЛЯ XRAY-ТЕСТА ---
xray_semaphore = threading.Semaphore(XRAY_MAX_PARALLEL)
_xray_port_counter = XRAY_PORT_BASE
_xray_port_lock = threading.Lock()
xray_available = False      # выставляется в main() если бинарь найден


# ============================================================
# СЛОЙ 1: Загрузка базы РКН и RU-прокси
# ============================================================

def load_ru_blocklist():
    """Загружает заблокированные подсети РКН из antifilter.download."""
    global blocked_networks

    print("📥 Загрузка базы РКН (antifilter.download)...", flush=True)
    nets = []
    for url in ANTIFILTER_URLS:
        try:
            resp = session.get(url, timeout=15, verify=False)
            count = 0
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    nets.append(ipaddress.IPv4Network(line, strict=False))
                    count += 1
                except ValueError:
                    try:
                        nets.append(ipaddress.IPv4Network(f"{line}/32", strict=False))
                        count += 1
                    except:
                        pass
            print(f"  ✅ {url.split('/')[-1]}: {count} подсетей", flush=True)
            if count > 1000:
                break
        except Exception as e:
            print(f"  ⚠️  Не удалось загрузить {url}: {e}", flush=True)

    blocked_networks = nets
    print(f"📊 Заблокированных подсетей РКН: {len(blocked_networks)}", flush=True)


# ============================================================
# СЛОЙ 1: Проверка IP по базе РКН
# ============================================================

def is_blocked_in_ru(ip_str):
    """Проверяет IP по загруженным подсетям РКН. Работает до пинга."""
    with _blocked_cache_lock:
        if ip_str in _blocked_cache:
            return _blocked_cache[ip_str]
    try:
        addr = ipaddress.IPv4Address(ip_str)
        result = any(addr in net for net in blocked_networks)
    except:
        result = False
    with _blocked_cache_lock:
        _blocked_cache[ip_str] = result
    return result



# ============================================================
# XRAY-ТЕСТ: реальная проверка туннеля
# ============================================================

def _get_xray_port():
    """Выдаёт уникальный порт для каждого потока."""
    global _xray_port_counter
    with _xray_port_lock:
        port = _xray_port_counter
        _xray_port_counter += 1
    return port


def _build_xray_config(config_link, socks_port):
    """
    Строит минимальный config.json для Xray из vless:// ссылки.
    Поддерживает: REALITY/tcp, TLS/tcp, TLS/ws, TLS/xhttp.
    """
    l = config_link.lower()
    h_m = re.search(r'@([^:/?#\s]+):(\d+)', config_link)
    s_m = re.search(r'[?&]sni=([^&#\s]*)', config_link, re.I)
    id_m = re.search(r'://([^@]+)@', config_link)
    pbk_m = re.search(r'[?&]pbk=([^&#\s]*)', config_link, re.I)
    sid_m = re.search(r'[?&]sid=([^&#\s]*)', config_link, re.I)
    fp_m = re.search(r'[?&]fp=([^&#\s]*)', config_link, re.I)
    path_m = re.search(r'[?&]path=([^&#\s]*)', config_link, re.I)
    flow_m = re.search(r'[?&]flow=([^&#\s]*)', config_link, re.I)
    type_m = re.search(r'[?&]type=([^&#\s]*)', config_link, re.I)

    if not h_m or not id_m:
        return None

    address = h_m.group(1)
    port = int(h_m.group(2))
    uuid = id_m.group(1)
    sni = s_m.group(1) if s_m else address
    fp = fp_m.group(1) if fp_m else "chrome"
    net_type = type_m.group(1) if type_m else "tcp"
    flow = flow_m.group(1) if flow_m else ""

    # TLS или REALITY
    if pbk_m:
        tls_settings = {
            "serverName": sni,
            "fingerprint": fp,
            "publicKey": pbk_m.group(1),
            "shortId": sid_m.group(1) if sid_m else "",
        }
        security = "reality"
    elif "security=tls" in l:
        tls_settings = {
            "serverName": sni,
            "fingerprint": fp,
            "allowInsecure": True,
        }
        security = "tls"
    else:
        tls_settings = {}
        security = "none"

    # Транспорт
    if net_type == "ws":
        path = requests.utils.unquote(path_m.group(1)) if path_m else "/"
        stream_settings = {
            "network": "ws",
            "security": security,
            "tlsSettings" if security == "tls" else "realitySettings": tls_settings,
            "wsSettings": {"path": path, "headers": {"Host": sni}},
        }
    elif net_type == "xhttp":
        path = requests.utils.unquote(path_m.group(1)) if path_m else "/"
        stream_settings = {
            "network": "xhttp",
            "security": security,
            "tlsSettings" if security == "tls" else "realitySettings": tls_settings,
            "xhttpSettings": {"path": path, "host": sni},
        }
    else:
        # tcp (REALITY + Vision, обычный tcp)
        stream_settings = {
            "network": "tcp",
            "security": security,
            "tlsSettings" if security == "tls" else "realitySettings": tls_settings,
        }

    # Убираем пустой ключ если security=none
    if security == "none":
        stream_settings.pop("tlsSettings", None)
        stream_settings.pop("realitySettings", None)

    outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": address,
                "port": port,
                "users": [{
                    "id": uuid,
                    "encryption": "none",
                    "flow": flow,
                }]
            }]
        },
        "streamSettings": stream_settings,
    }

    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": "socks",
            "port": socks_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [outbound],
        "routing": {
            "rules": [{"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}]
        },
    }
    return config


def xray_test(config_link):
    """
    Запускает Xray с конфигом и пробует скачать 204-страницу через SOCKS5.
    Возвращает True если туннель реально работает, False иначе.
    Если xray недоступен — всегда возвращает True (не блокируем).
    """
    if not xray_available:
        return True

    import subprocess, tempfile

    socks_port = _get_xray_port()
    xray_cfg = _build_xray_config(config_link, socks_port)
    if not xray_cfg:
        return True  # не смогли построить конфиг — не блокируем

    proc = None
    tmp = None
    with xray_semaphore:
        try:
            tmp = tempfile.NamedTemporaryFile(
                mode='w', suffix='.json', delete=False, prefix='xray_cfg_'
            )
            json.dump(xray_cfg, tmp)
            tmp.flush()
            tmp.close()

            proc = subprocess.Popen(
                [XRAY_BINARY, "run", "-config", tmp.name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            time.sleep(XRAY_STARTUP_WAIT)

            if proc.poll() is not None:
                # Xray сразу упал — конфиг нерабочий
                stats['xray_failed'] += 1
                return False

            proxies = {
                "http":  f"socks5://127.0.0.1:{socks_port}",
                "https": f"socks5://127.0.0.1:{socks_port}",
            }
            r = requests.get(
                XRAY_TEST_URL,
                proxies=proxies,
                timeout=XRAY_TIMEOUT - XRAY_STARTUP_WAIT,
                verify=False,
            )
            h_m = re.search(r'@([^:/?#\s]+):(\d+)', config_link)
            host_log = h_m.group(1) if h_m else "?"
            port_log = h_m.group(2) if h_m else "?"
            print(f"[XRAY] {host_log}:{port_log} | HTTP: {r.status_code} | байт: {len(r.content)}", flush=True)
            if r.status_code in (200, 204):
                return True
            else:
                stats['xray_failed'] += 1
                return False

        except requests.exceptions.ConnectionError:
            stats['xray_failed'] += 1
            return False
        except Exception:
            # Любая другая ошибка — не блокируем конфиг
            return True
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except:
                    proc.kill()
            if tmp:
                try:
                    os.unlink(tmp.name)
                except:
                    pass


# ============================================================
# ОРИГИНАЛЬНЫЕ ФУНКЦИИ (без изменений)
# ============================================================

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
    if re.search(r':(443|80)/\?', l):
        return True
    if "/??" in l:
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
        with socket.create_connection((host, port), timeout=1.2) as sock:
            with context.wrap_socket(sock, server_hostname=sni if sni else None) as ssock:
                return int((time.perf_counter() - start) * 1000)
    except:
        return None


def full_ping_analysis(host, port, sni, initial_ping, min_limit, max_limit):
    pings = [initial_ping]

    if initial_ping < min_limit or initial_ping > max_limit:
        stats['ping_out_of_range'] += 1
        return None

    max_attempts = 3
    try:
        for _ in range(max_attempts):
            if stop_event.is_set():
                return None
            time.sleep(0.15)
            p = fast_ping(host, port, sni)
            if p:
                if p < min_limit or p > max_limit:
                    stats['ping_out_of_range'] += 1
                    return None
                pings.append(p)

        if len(pings) < 4:
            return None

        avg = sum(pings) // len(pings)
        jit = sum(abs(p - avg) for p in pings) // len(pings)

        if jit > (avg * MAX_JITTER_RATIO) or jit > MAX_JITTER:
            stats['jitter_failed'] += 1
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


def get_config_type(ip_cc, is_white):
    if is_white:
        if ip_cc == "RU":
            return "ru_sni"
        else:
            return "nonru_sni"
    else:
        return "others"


def get_subnet16_limit(config_type):
    limits = {
        "ru_sni": MAX_PER_SUBNET16_RU_SNI,
        "nonru_sni": MAX_PER_SUBNET16_NONRU_SNI,
        "others": MAX_PER_SUBNET16_OTHERS
    }
    return limits.get(config_type, MAX_PER_SUBNET16_OTHERS)


def check_isp_info(ip_str):
    global last_api_call, api_calls_count
    with lock:
        if ip_str in ip_cache:
            return ip_cache[ip_str]
    with api_semaphore:
        try:
            for attempt in range(2):
                if stop_event.is_set():
                    return None, False
                if attempt > 0:
                    time.sleep(1.0)
                with lock:
                    elapsed = time.perf_counter() - last_api_call
                    sleep_time = max(0.0, 1.4 - elapsed)
                    last_api_call = time.perf_counter()
                    api_calls_count += 1
                if sleep_time > 0:
                    time.sleep(sleep_time)
                resp = session.get(f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,isp,org,as,asname,hosting", timeout=5)
                r = resp.json()
                if r.get("status") == "success":
                    full_info = f"{r.get('isp')} {r.get('org')} {r.get('as')} {r.get('asname')}".lower()
                    is_bad_hosting = any(word in full_info for word in BAD_HOSTING_KEYWORDS)
                    is_banned_pattern = any(pattern.lower() in full_info for pattern in BANNED_ASNAME_PATTERNS)
                    is_banned = is_bad_hosting or is_banned_pattern
                    is_hosting_flag = r.get("hosting", False) and not is_bad_hosting
                    res = (r.get("countryCode"), "BANNED" if is_banned else is_hosting_flag)
                    with lock:
                        ip_cache[ip_str] = res
                    return res
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
    if is_hosting is True:
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
        return [l.strip() for l in re.findall(r'(?:vless|ssr|tuic|hysteria|hysteria2)://[^\s]+', resp)]
    except:
        return []


def get_sni_limit(is_white, ip_cc):
    is_ru = (ip_cc == "RU")
    if is_white:
        if is_ru:
            return MAX_SAME_SNI_RU_RU
        return MAX_SAME_SNI_RU
    return MAX_SAME_SNI_WORLD


def can_add_hosting(is_hosting, target_list):
    if is_hosting is True:
        count = sum(1 for r in target_list if r['is_hosting'] is True)
        return count < MAX_HOST_CONFIGS
    return True


def try_add_to_lists(entry):
    global ru_vlm_count, ru_vlm2_count, xhttp_count

    is_ru = (entry['country'] == 'RU')
    is_xhttp = entry['is_xhttp']
    is_hosting = entry['is_hosting']

    added_vlm = False
    added_vlm2 = False

    if is_xhttp:
        if is_ru:
            if ru_vlm2_count < MAX_RU_CONFIGS and xhttp_count < MAX_XHTTP and can_add_hosting(is_hosting, vlm2_results):
                vlm2_results.append(entry)
                ru_vlm2_count += 1
                xhttp_count += 1
                added_vlm2 = True
        else:
            if xhttp_count < MAX_XHTTP and len(vlm2_results) < MAX_CONFIGS and can_add_hosting(is_hosting, vlm2_results):
                vlm2_results.append(entry)
                xhttp_count += 1
                added_vlm2 = True
    else:
        if is_ru:
            if ru_vlm_count < MAX_RU_CONFIGS and len(vlm_results) < MAX_CONFIGS and can_add_hosting(is_hosting, vlm_results):
                vlm_results.append(entry)
                ru_vlm_count += 1
                added_vlm = True
        elif len(vlm_results) < MAX_CONFIGS and can_add_hosting(is_hosting, vlm_results):
            vlm_results.append(entry)
            added_vlm = True

        reserved_for_xhttp = max(0, MIN_XHTTP - xhttp_count)
        vlm2_space = MAX_CONFIGS - reserved_for_xhttp
        if is_ru:
            if ru_vlm2_count < MAX_RU_CONFIGS and len(vlm2_results) < vlm2_space and can_add_hosting(is_hosting, vlm2_results):
                vlm2_results.append(entry)
                ru_vlm2_count += 1
                added_vlm2 = True
        elif len(vlm2_results) < vlm2_space and can_add_hosting(is_hosting, vlm2_results):
            vlm2_results.append(entry)
            added_vlm2 = True

    return added_vlm or added_vlm2


def check_completion():
    vlm_done = (ru_vlm_count >= MIN_RU_CONFIGS and len(vlm_results) >= MAX_CONFIGS)
    vlm2_done = (ru_vlm2_count >= MIN_RU_CONFIGS and xhttp_count >= MIN_XHTTP and len(vlm2_results) >= MAX_CONFIGS)
    if vlm_done and vlm2_done:
        stop_event.set()
        return True
    return False


def validate(config, is_priority, is_white):
    if stop_event.is_set():
        stats['stopped'] += 1
        return

    if is_technically_broken(config):
        stats['broken'] += 1
        return

    host, port, sni, cid = get_config_details(config)
    if not host or not sni:
        stats['no_details'] += 1
        return

    if host in failed_ips:
        stats['failed_ip_cache'] += 1
        return

    # ── СЛОЙ 1: фильтр РКН (до пинга — быстро) ──────────────────────────────
    if is_blocked_in_ru(host):
        stats['blocked_rkn'] += 1
        return

    is_xhttp = "xhttp" in config.lower()
    subnet = ".".join(host.split(".")[:3])
    subnet16 = ".".join(host.split(".")[:2])

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

        if subnet_counts[subnet] >= MAX_PER_SUBNET:
            stats['subnet_limit'] += 1
            return

        if id_counts[cid] >= MAX_PER_ID:
            stats['id_limit'] += 1
            return

    # Первый пинг
    p1 = fast_ping(host, port, sni)
    initial_max_p = MAX_WORLD_PING_XHTTP if is_xhttp else MAX_WORLD_PING
    if not p1 or p1 > initial_max_p:
        with lock:
            failed_subnets[subnet] += 1
            failed_ips.add(host)
        stats['first_ping_failed'] += 1
        return

    # Проверка ISP
    ip_cc, ip_h_stat = check_isp_info(host)
    if not ip_cc or ip_h_stat == "BANNED" or stop_event.is_set():
        stats['isp_banned'] += 1
        return

    # Проверка лимита подсети /16
    config_type = get_config_type(ip_cc, is_white)
    subnet16_limit = get_subnet16_limit(config_type)

    subnet16_reserved = False
    with lock:
        if subnet16_counts[subnet16][config_type] >= subnet16_limit:
            stats['subnet16_limit'] += 1
            return
        subnet16_counts[subnet16][config_type] += 1
        subnet16_reserved = True

    # Атомарная резервация SNI
    sni_reserved = False
    with lock:
        sni_limit = get_sni_limit(is_white, ip_cc)
        if sni_usage_counts[sni] >= sni_limit:
            stats['sni_limit'] += 1
            return
        sni_usage_counts[sni] += 1
        sni_reserved = True

    # Определяем строгие лимиты
    is_ru = (ip_cc == "RU")
    if is_xhttp:
        min_p = MIN_RU_PING if is_ru else MIN_WORLD_PING
        max_p = MAX_RU_PING_XHTTP if is_ru else MAX_WORLD_PING_XHTTP
    else:
        min_p = MIN_RU_PING if is_ru else MIN_WORLD_PING
        max_p = MAX_RU_PING if is_ru else MAX_WORLD_PING

    # Полный анализ пинга
    full = full_ping_analysis(host, port, sni, p1, min_p, max_p)
    if not full:
        if sni_reserved:
            with lock:
                sni_usage_counts[sni] -= 1
        if subnet16_reserved:
            with lock:
                subnet16_counts[subnet16][config_type] -= 1
        return

    # ── XRAY-ТЕСТ: реальная проверка туннеля ─────────────────────────────────
    if not xray_test(config):
        if sni_reserved:
            with lock:
                sni_usage_counts[sni] -= 1
        if subnet16_reserved:
            with lock:
                subnet16_counts[subnet16][config_type] -= 1
        return

    # Финальное добавление
    with lock:
        if host in seen_ips:
            if sni_reserved:
                sni_usage_counts[sni] -= 1
            if subnet16_reserved:
                subnet16_counts[subnet16][config_type] -= 1
            stats['race_duplicate'] += 1
            return

        if failed_subnets[subnet] >= MAX_FAILED_PER_SUBNET:
            if sni_reserved:
                sni_usage_counts[sni] -= 1
            if subnet16_reserved:
                subnet16_counts[subnet16][config_type] -= 1
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

        if try_add_to_lists(entry):
            seen_ips.add(host)
            subnet_counts[subnet] += 1
            id_counts[cid] += 1

            host_tag = " (X)" if is_xhttp else ""
            sni_tag = " SNI-RU" if is_white else ""
            print(f"[FOUND{host_tag}] {ip_cc} | {full[0]}ms | {host}{sni_tag}", flush=True)
            stats['added'] += 1
            check_completion()
        else:
            sni_usage_counts[sni] -= 1
            if subnet16_reserved:
                subnet16_counts[subnet16][config_type] -= 1
            stats['not_added'] += 1


def fetch_group_data(urls):
    raw = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(fetch_raw_configs, u) for u in set(urls)]
        for f in concurrent.futures.as_completed(futures):
            raw.extend(f.result())
    unique = list(set(raw))
    random.shuffle(unique)
    return unique


def finalize_list(results, is_vlm2=False):
    all_ru_sni = sorted([r for r in results if r['country'] == 'RU' and r['white_sni']], key=lambda x: x['ping'])
    top_fixed = all_ru_sni[:MAX_TOP_RU_SNI]

    xhttp_bucket = []
    if is_vlm2:
        xhttp_bucket = sorted([r for r in results if r.get('is_xhttp')], key=lambda x: x['ping'])

    top_fixed_links = {r['link'] for r in top_fixed}
    xhttp_bucket_links = {r['link'] for r in xhttp_bucket}

    ru_sni_configs = []
    non_ru_sni_configs = []

    for r in results:
        if r['link'] in top_fixed_links or r['link'] in xhttp_bucket_links:
            continue
        if r['white_sni']:
            ru_sni_configs.append(r)
        else:
            non_ru_sni_configs.append(r)

    ru_sni_configs.sort(key=lambda x: x['ping'])
    non_ru_sni_configs.sort(key=lambda x: x['ping'])

    final = list(top_fixed)
    final_links = {r['link'] for r in final}
    current_ru_sni_total = len(top_fixed)

    while len(final) < MAX_CONFIGS:
        added_any = False

        if is_vlm2 and xhttp_bucket and len(final) == len(top_fixed):
            count = 0
            while count < INTERLEAVE_STEP and len(final) < MAX_CONFIGS and xhttp_bucket:
                config = xhttp_bucket.pop(0)
                if config['link'] not in final_links:
                    final.append(config)
                    final_links.add(config['link'])
                    count += 1
                    added_any = True

        count = 0
        while count < INTERLEAVE_STEP and len(final) < MAX_CONFIGS and non_ru_sni_configs:
            config = non_ru_sni_configs.pop(0)
            if config['link'] not in final_links:
                final.append(config)
                final_links.add(config['link'])
                count += 1
                added_any = True

        count = 0
        while count < INTERLEAVE_STEP and len(final) < MAX_CONFIGS and ru_sni_configs:
            if current_ru_sni_total >= MAX_TOTAL_SNI_RU:
                break
            config = ru_sni_configs.pop(0)
            if config['link'] not in final_links:
                final.append(config)
                final_links.add(config['link'])
                count += 1
                added_any = True
                current_ru_sni_total += 1

        if not added_any:
            break

    speed_rating = {r['link']: rank + 1 for rank, r in enumerate(sorted(final, key=lambda x: x['ping']))}
    return [rename_config(r['link'], r['country'], speed_rating[r['link']], r['is_hosting'], r['white_sni']) for r in final]


def print_statistics():
    print("\n--- 📊 СТАТИСТИКА ---", flush=True)
    print(f"Добавлено: {stats['added']}", flush=True)
    print(f"Запросов к ip-api: {api_calls_count} (кэш попаданий: {stats['duplicate_ip'] + stats['race_duplicate']})", flush=True)
    print(f"Технически битые: {stats['broken']}", flush=True)
    print(f"Без деталей: {stats['no_details']}", flush=True)
    print(f"Дубликаты IP: {stats['duplicate_ip']}", flush=True)
    print(f"Кэш неудачных IP: {stats['failed_ip_cache']}", flush=True)
    print(f"Первый пинг провален: {stats['first_ping_failed']}", flush=True)
    print(f"ISP забанен: {stats['isp_banned']}", flush=True)
    print(f"Пинг вне диапазона: {stats['ping_out_of_range']}", flush=True)
    print(f"Jitter провален: {stats['jitter_failed']}", flush=True)
    print(f"Лимиты SNI: {stats['sni_limit']}", flush=True)
    print(f"Лимиты подсети: {stats['subnet_limit']}", flush=True)
    print(f"Подсеть забанена: {stats['subnet_banned']}", flush=True)
    print(f"Не добавлено (нет места): {stats['not_added']}", flush=True)
    # НОВОЕ: статистика RU-проверки
    print(f"Заблокировано РКН: {stats['blocked_rkn']}", flush=True)
    print(f"Не прошло Xray-тест: {stats['xray_failed']}", flush=True)
    print(f"\nVLM: {len(vlm_results)} (RU: {ru_vlm_count}, HOST: {sum(1 for r in vlm_results if r['is_hosting'] is True)})", flush=True)
    print(f"VLM2: {len(vlm2_results)} (RU: {ru_vlm2_count}, XHTTP: {xhttp_count}, HOST: {sum(1 for r in vlm2_results if r['is_hosting'] is True)})", flush=True)


def main():
    global sni_domains, xray_available

    start_total = time.perf_counter()
    print(f"--- 🟢 ЗАПУСК [{offset}] ---", flush=True)

    # Проверяем наличие Xray
    import subprocess
    try:
        result = subprocess.run([XRAY_BINARY, "version"], capture_output=True, timeout=5)
        xray_available = result.returncode == 0
    except:
        xray_available = False
    print(f"{'✅' if xray_available else '⚠️ '} Xray: {'доступен' if xray_available else 'не найден, тест отключён'}", flush=True)

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

    # НОВОЕ: загружаем базу РКН и RU-прокси один раз перед основным циклом
    load_ru_blocklist()

    raw_extra, raw_std = fetch_group_data(extra_urls), fetch_group_data(std_urls)
    print(f"Уникальных конфигов: Extra={len(raw_extra)}, Std={len(raw_std)}", flush=True)

    raw_nonwhite = list(set(raw_extra + raw_std))
    random.shuffle(raw_nonwhite)
    print(f"Не SNI-RU (объединённая корзина): {len(raw_nonwhite)}", flush=True)

    check_order = [
        (raw_extra, True, True),
        (raw_std, False, True),
        (raw_nonwhite, True, False)
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

    print_statistics()

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
