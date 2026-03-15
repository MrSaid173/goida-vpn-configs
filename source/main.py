# mine mine mine mine mine mine mine

import os
import re
import base64
import json
import time
import socket
import ssl
import random
import subprocess
import tempfile
import threading
import concurrent.futures
import ipaddress
from collections import defaultdict
from datetime import datetime

import urllib3
import requests
import zoneinfo
from github import Github, Auth

# --- НАСТРОЙКИ ---
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MrSaid173/golden-paths_configs"
FILENAME_VLM = "vlm"
FILENAME_VLM2 = "vlm2"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
SECONDARY_WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt"

# --- ЛИМИТЫ БРОНИРОВАНИЯ ---
MIN_XHTTP = 0
MAX_XHTTP = 3
MIN_RU_CONFIGS = 6
MAX_RU_CONFIGS = 6
MIN_HOST_CONFIGS = 0
MAX_HOST_CONFIGS = 3

INTERLEAVE_STEP = 3
EXCLUDED_SNI_DOMAINS = ["userapi", "splitter.wb.ru"]
BAD_HOSTING_KEYWORDS = [
    "cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google",
    "microsoft", "ovh", "linode", "servers", "work", "oracle", "leaseweb",
    "m247", "akamai", "host", "baykov", "dataforest",
]

BANNED_ASNAME_PATTERNS = [
    "-ru", "-ua", "-by", "-kz", "-uz", "-ge", "-am", "-az", "-md", "-tj", "-kg", "-tm",
    "-us", "-ca", "-mx", "-br", "-ar", "-cl", "-co", "-pe", "-ve",
    #"-de", "-nl", "-gb", "-uk", "-fr", "-it", "-es", "-pl", "-at", "-ch", "-se", "-no",
    #"-fi", "-dk", "-ie", "-pt", "-be", "-cz", "-hu", "-ro", "-bg", "-gr", "-tr", "-ee",
    #"-lv", "-lt", "-si", "-sk", "-hr", "-rs", "-me", "-ba", "-al", "-is", "-lu", "-mt",
    #"-cn", "-hk", "-sg", "-jp", "-kr", "-in", "-tw", "-vn", "-th", "-my", "-ph", "-id",
    #"-ae", "-il", "-sa", "-ir", "-iq", "-jo", "-kw", "-qa", "-om", "-ye",
    "-au", "-nz", "-za", "-ng", "-eg", "-ke", "-ma", "-dz", "-tn",
]

# Настройки Jitter
MAX_JITTER = 100
MAX_JITTER_RATIO = 0.4

# Настройки повтора SNI-RU
RU_RETRY_WAIT       = 480  # секунд ожидания перед каждой повторной попыткой
RU_RETRY_MAX        = 1    # максимум попыток добора SNI-RU
CACHE_RESET_MODE    = 1    # 0 - не очищать, 1 - очищать наполовину, 2 - очищать полностью

# Настройки конфигураций
MAX_CONFIGS = 30
MAX_TOTAL_SNI_RU = MAX_CONFIGS // 2
MAX_TOP_RU_SNI = MAX_RU_CONFIGS

MAX_PER_SUBNET = 2
MAX_PER_SUBNET16_RU_SNI = 1
MAX_PER_SUBNET16_NONRU_SNI = 5
MAX_PER_SUBNET16_OTHERS = 7

MAX_PER_ID = 6
MAX_FAILED_PER_SUBNET = 6

# Лимиты на повторение SNI
MAX_SAME_SNI_RU_RU = 1  # RU IP + white SNI
MAX_SAME_SNI_RU = 8     # Не-RU IP + white SNI
MAX_SAME_SNI_WORLD = 5  # Любой IP + не-white SNI

MIN_RU_PING, MAX_RU_PING = 100.0, 600.0
MIN_WORLD_PING, MAX_WORLD_PING = 25.0, 750.0

# Расширенные лимиты для XHTTP
MAX_RU_PING_XHTTP = MAX_RU_PING + 120
MAX_WORLD_PING_XHTTP = MAX_WORLD_PING + 120

# Таймауты (секунды)
FAST_PING_TIMEOUT = 1.2
FULL_PING_PAUSE_MIN   = 0.15  # минимальная пауза
FULL_PING_PAUSE_STEP  = 0.02  # расстояние между шагами
FULL_PING_PAUSE_COUNT = 4     # количество шагов → [0.15, 0.17, 0.19, 0.21]
FULL_PING_PAUSES = [round(FULL_PING_PAUSE_MIN + i * FULL_PING_PAUSE_STEP, 4) for i in range(FULL_PING_PAUSE_COUNT)]
FULL_PING_ATTEMPTS = 2
FULL_PING_MIN_SAMPLES = 3

# Rate-limit для ip-api.com
API_RATE_LIMIT_INTERVAL = 1.5  # минимальный интервал между запросами

# --- НАСТРОЙКИ RU-ПРОВЕРКИ ---
ANTIFILTER_URLS = [
    "https://antifilter.download/list/subnet.lst",
    "https://antifilter.download/list/allyouneed.lst",
    "https://antifilter.download/list/ip.lst",
    "https://antifilter.download/list/ipresolve.lst",
]

# --- НАСТРОЙКИ XRAY-ТЕСТА ---
XRAY_BINARY = os.environ.get("XRAY_BINARY", "/tmp/xray/xray")
XRAY_TEST_URL_RU = "http://cp.cloudflare.com/" 
XRAY_TEST_URL_WORLD = "http://cp.cloudflare.com/"
XRAY_STARTUP_WAIT = 3.0   # максимум секунд ожидания старта xray
XRAY_HTTP_TIMEOUT = 2.2     # секунд на HTTP запрос через туннель
XRAY_STARTUP_CHECK_INTERVAL = 0.1  # интервал проверки готовности xray (секунд)
XRAY_MAX_PARALLEL = 4     # максимум одновременных xray-процессов
XRAY_PORT_BASE = 10000    # стартовый порт для SOCKS5, каждый тред берёт свой
XRAY_PROCESS_TIMEOUT = 5  # таймаут на запуск xray version

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
stats_lock = threading.Lock()   # отдельный лок для счётчиков статистики
api_semaphore = threading.Semaphore(3)
stop_event = threading.Event()
sni_ru_done_event = threading.Event()  # сигнал завершения фазы SNI-RU

# Кэши и счетчики (защищены основным lock)
ip_cache = {}
failed_ips = set()
failed_subnets = defaultdict(int)
seen_ips = set()
subnet_counts = defaultdict(int)
subnet16_counts = defaultdict(lambda: defaultdict(int))
id_counts = defaultdict(int)
sni_usage_counts = defaultdict(int)

# Флаг режима повтора SNI-RU
sni_ru_retry_mode = False

# Кэш уже проверенных конфигов (ключ: host:port:uuid:sni)
checked_configs = set()

# Счетчики для vlm/vlm2 (защищены основным lock)
ru_vlm_count = 0
ru_vlm2_count = 0
xhttp_count = 0
host_vlm_count = 0   # количество hosting конфигов в vlm
host_vlm2_count = 0  # количество hosting конфигов в vlm2
sni_vlm_count = 0    # количество white_sni конфигов в vlm
sni_vlm2_count = 0   # количество white_sni конфигов в vlm2

vlm_results = []
vlm2_results = []

last_api_call = 0.0

# Статистика для отладки (защищена stats_lock)
stats = defaultdict(int)
api_calls_count = 0

# --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ДЛЯ RU-ПРОВЕРКИ ---
blocked_networks = []       # список IPv4Network из antifilter
_blocked_cache: dict = {}
_blocked_cache_lock = threading.Lock()

# --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ДЛЯ XRAY-ТЕСТА ---
xray_semaphore = threading.Semaphore(XRAY_MAX_PARALLEL)
_xray_port_counter = XRAY_PORT_BASE
_xray_port_lock = threading.Lock()
xray_available = False      # выставляется в main() если бинарь найден


def _inc_stat(key: str, amount: int = 1) -> None:
    """Потокобезопасное увеличение счётчика статистики."""
    with stats_lock:
        stats[key] += amount


def _partial_cache_reset() -> None:
    """
    Сброс failed_ips и части checked_configs перед повторным поиском SNI-RU конфигов.
    Поведение определяется CACHE_RESET_MODE:
      0 - не очищать
      1 - очищать failed_ips наполовину
      2 - очищать failed_ips полностью
    Принятые конфиги не трогаются никогда.
    """
    global failed_ips, checked_configs

    if CACHE_RESET_MODE == 0:
        print("🔄 Сброс кэшей пропущен (CACHE_RESET_MODE=0)", flush=True)
        return

    with lock:
        working_ips = {
            re.search(r'@([^:/?#\s]+):', r['link']).group(1)
            for r in vlm_results + vlm2_results
            if re.search(r'@([^:/?#\s]+):', r['link'])
        }
        # Ключи принятых конфигов — не трогаем в checked_configs
        working_keys = set()
        for r in vlm_results + vlm2_results:
            m = re.search(r'@([^:/?#\s]+):(\d+)', r['link'])
            s = re.search(r'[?&]sni=([^&#\s]*)', r['link'], re.I)
            cid = re.search(r'://([^@]+)@', r['link'])
            if m:
                working_keys.add(f"{m.group(1)}:{m.group(2)}:{cid.group(1) if cid else ''}:{s.group(1).lower() if s else ''}")

        non_working_failed = list(failed_ips - working_ips)
        non_working_checked = list(checked_configs - working_keys)

        if CACHE_RESET_MODE == 1:
            failed_ips -= set(random.sample(non_working_failed, len(non_working_failed) // 2))
            for k in random.sample(non_working_checked, len(non_working_checked) // 2):
                checked_configs.discard(k)
            print("🔄 Кэши сброшены (failed_ips и checked_configs наполовину)", flush=True)
        elif CACHE_RESET_MODE == 2:
            failed_ips -= set(non_working_failed)
            checked_configs -= set(non_working_checked)
            print("🔄 Кэши сброшены (failed_ips и checked_configs полностью)", flush=True)


# ============================================================
# СЛОЙ 1: Загрузка базы РКН и RU-прокси
# ============================================================

def load_ru_blocklist() -> None:
    """Загружает заблокированные подсети РКН из antifilter.download."""
    global blocked_networks

    print("📥 Загрузка базы РКН (antifilter.download)...", flush=True)
    nets: list[ipaddress.IPv4Network] = []
    for url in ANTIFILTER_URLS:
        try:
            resp = session.get(url, timeout=15, verify=False)
            resp.raise_for_status()
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
                    except ValueError:
                        pass
            print(f"  ✅ {url.split('/')[-1]}: {count} записей", flush=True)
        except requests.RequestException as e:
            print(f"  ⚠️  Не удалось загрузить {url}: {e}", flush=True)

    # Сортируем для бинарного поиска (по int-представлению сети)
    blocked_networks = sorted(nets, key=lambda n: int(n.network_address))
    print(f"📊 Заблокированных подсетей РКН: {len(blocked_networks)}", flush=True)


# ============================================================
# СЛОЙ 1: Проверка IP по базе РКН  (бинарный поиск)
# ============================================================

def is_blocked_in_ru(ip_str: str) -> bool:
    """
    Проверяет IP по загруженным подсетям РКН.
    Использует бинарный поиск вместо линейного перебора — O(log n).
    """
    with _blocked_cache_lock:
        if ip_str in _blocked_cache:
            return _blocked_cache[ip_str]

    result = False
    try:
        addr = ipaddress.IPv4Address(ip_str)
        addr_int = int(addr)
        # Бинарный поиск: ищем правую границу по network_address
        lo, hi = 0, len(blocked_networks) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            net = blocked_networks[mid]
            net_int = int(net.network_address)
            if net_int <= addr_int:
                if addr in net:
                    result = True
                    break
                lo = mid + 1
            else:
                hi = mid - 1
    except ValueError:
        result = False

    with _blocked_cache_lock:
        _blocked_cache[ip_str] = result
    return result


# ============================================================
# XRAY-ТЕСТ: реальная проверка туннеля
# ============================================================

def _get_xray_port() -> int:
    """Выдаёт уникальный порт для каждого потока."""
    global _xray_port_counter
    with _xray_port_lock:
        port = _xray_port_counter
        _xray_port_counter += 1
    return port


def _build_xray_config(config_link: str, socks_port: int) -> dict | None:
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
    enc_m  = re.search(r'[?&]packetEncoding=([^&#\s]*)', config_link, re.I)

    if not h_m or not id_m:
        return None

    address = h_m.group(1)
    port = int(h_m.group(2))
    uuid = id_m.group(1)
    sni = s_m.group(1) if s_m else address
    fp = fp_m.group(1) if fp_m else "chrome"
    net_type = type_m.group(1) if type_m else "tcp"
    flow = flow_m.group(1) if flow_m else ""
    packet_encoding = enc_m.group(1) if enc_m else None

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

    tls_key = "tlsSettings" if security == "tls" else "realitySettings"

    # Транспорт
    if net_type == "ws":
        path = requests.utils.unquote(path_m.group(1)) if path_m else "/"
        stream_settings = {
            "network": "ws",
            "security": security,
            tls_key: tls_settings,
            "wsSettings": {"path": path, "headers": {"Host": sni}},
        }
    elif net_type == "xhttp":
        path = requests.utils.unquote(path_m.group(1)) if path_m else "/"
        stream_settings = {
            "network": "xhttp",
            "security": security,
            tls_key: tls_settings,
            "xhttpSettings": {"path": path, "host": sni},
        }
    else:
        # tcp (REALITY + Vision, обычный tcp)
        stream_settings = {
            "network": "tcp",
            "security": security,
            tls_key: tls_settings,
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
                    **({"packetEncoding": packet_encoding} if packet_encoding else {}),
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
        "outbounds": [outbound, {"tag": "direct", "protocol": "freedom"}],
    }
    return config


def xray_test(config_link: str, is_ru: bool = False) -> bool:
    """
    Запускает Xray с конфигом и пробует достучаться до тестового ресурса через SOCKS5.
    - RU-конфиги проверяются через gosuslugi.ru (доступен только из РФ).
    - Остальные — через cp.cloudflare.com (глобальный, лёгкий 204).
    Возвращает True если туннель реально работает, False иначе.
    Если xray недоступен — всегда возвращает True (не блокируем).
    """
    if not xray_available:
        return True

    socks_port = _get_xray_port()
    xray_cfg = _build_xray_config(config_link, socks_port)
    if not xray_cfg:
        return True  # не смогли построить конфиг — не блокируем

    proc = None
    tmp_path = None
    with xray_semaphore:
        try:
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.json', delete=False, prefix='xray_cfg_'
            ) as tmp:
                json.dump(xray_cfg, tmp)
                tmp_path = tmp.name

            proc = subprocess.Popen(
                [XRAY_BINARY, "run", "-config", tmp_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Умное ожидание: проверяем готовность SOCKS5 порта каждые XRAY_STARTUP_CHECK_INTERVAL
            deadline = time.perf_counter() + XRAY_STARTUP_WAIT
            xray_ready = False
            while time.perf_counter() < deadline:
                if proc.poll() is not None:
                    # Xray сразу упал — конфиг нерабочий
                    _inc_stat('xray_failed')
                    return False
                try:
                    with socket.create_connection(("127.0.0.1", socks_port), timeout=0.1):
                        xray_ready = True
                        break
                except OSError:
                    time.sleep(XRAY_STARTUP_CHECK_INTERVAL)

            if not xray_ready:
                _inc_stat('xray_failed')
                return False

            proxies = {
                "http":  f"socks5://127.0.0.1:{socks_port}",
                "https": f"socks5://127.0.0.1:{socks_port}",
            }
            test_url = XRAY_TEST_URL_RU if is_ru else XRAY_TEST_URL_WORLD
            r = requests.get(
                test_url,
                proxies=proxies,
                timeout=XRAY_HTTP_TIMEOUT,
                verify=False,
            )
            if r.status_code in (200, 204):
                return True
            _inc_stat('xray_failed')
            return False

        except requests.exceptions.ConnectionError:
            _inc_stat('xray_failed')
            return False
        except Exception:
            _inc_stat('xray_failed')
            return False
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass


# ============================================================
# ОРИГИНАЛЬНЫЕ ФУНКЦИИ
# ============================================================

def is_valid_ipv4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def is_technically_broken(link: str) -> bool:
    l = link.lower()
    if "type=" not in l:
        return True
    if "type=http" in l and "type=httpupgrade" not in l:
        return True
    if "type=splithttp" in l:
        return True
    #if re.search(r':(443|80)/\?', l):
        #return True
    #if "/??" in l:
        #return True
    if "host=" in l: #or "packetencoding=" in l or "type=raw" in l:
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
    if "security=tls" in l or "security=reality" in l:
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


def fast_ping(host: str, port: int, sni: str) -> int | None:
    try:
        start = time.perf_counter()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=FAST_PING_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=sni if sni else None):
                return int((time.perf_counter() - start) * 1000)
    except (socket.timeout, socket.error, ssl.SSLError, OSError):
        return None


def full_ping_analysis(
    host: str, port: int, sni: str,
    initial_ping: int, min_limit: float, max_limit: float
) -> tuple[int, int] | None:
    pings = [initial_ping]

    if initial_ping < min_limit or initial_ping > max_limit:
        _inc_stat('ping_out_of_range')
        return None

    try:
        used_pauses = []
        for i in range(FULL_PING_ATTEMPTS):
            if stop_event.is_set():
                return None
            # Перед последней паузой: если все предыдущие одинаковые — исключаем это значение
            if i == FULL_PING_ATTEMPTS - 1 and len(used_pauses) >= 2 and len(set(used_pauses)) == 1:
                options = [p for p in FULL_PING_PAUSES if p != used_pauses[0]]
            else:
                options = FULL_PING_PAUSES
            pause = random.choice(options)
            used_pauses.append(pause)
            time.sleep(pause)
            p = fast_ping(host, port, sni)
            if p is not None:
                if p < min_limit or p > max_limit:
                    _inc_stat('ping_out_of_range')
                    return None
                pings.append(p)

        if len(pings) < FULL_PING_MIN_SAMPLES:
            return None

        avg = sum(pings) // len(pings)
        jit = sum(abs(p - avg) for p in pings) // len(pings)

        if jit > (avg * MAX_JITTER_RATIO) or jit > MAX_JITTER:
            _inc_stat('jitter_failed')
            return None

        return avg, jit
    except Exception:
        return None


def get_config_details(link: str) -> tuple:
    try:
        clean_link = re.sub(r'[^\x20-\x7E]', '', link).strip()
        cid_match = re.search(r'://([^@]+)@', clean_link)
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', clean_link)
        s_m = re.search(r'[?&]sni=([^&#\s]*)', clean_link)
        if h_m and is_valid_ipv4(h_m.group(1)):
            sni = s_m.group(1).lower().split('?')[0].split('&')[0] if s_m else ""
            return h_m.group(1), int(h_m.group(2)), sni, cid_match.group(1) if cid_match else ""
    except (AttributeError, ValueError):
        pass
    return None, None, None, None


def get_config_type(ip_cc: str, is_white: bool) -> str:
    if is_white:
        return "ru_sni" if ip_cc == "RU" else "nonru_sni"
    return "others"


def get_subnet16_limit(config_type: str) -> int:
    limits = {
        "ru_sni": MAX_PER_SUBNET16_RU_SNI,
        "nonru_sni": MAX_PER_SUBNET16_NONRU_SNI,
        "others": MAX_PER_SUBNET16_OTHERS,
    }
    return limits.get(config_type, MAX_PER_SUBNET16_OTHERS)


def check_isp_info(ip_str: str) -> tuple:
    global last_api_call, api_calls_count

    with lock:
        if ip_str in ip_cache:
            return ip_cache[ip_str]

    with api_semaphore:
        for attempt in range(2):
            if stop_event.is_set():
                return None, False
            if attempt > 0:
                time.sleep(1.0)
            try:
                with lock:
                    elapsed = time.perf_counter() - last_api_call
                    sleep_time = max(0.0, API_RATE_LIMIT_INTERVAL - elapsed)
                    last_api_call = time.perf_counter()
                    api_calls_count += 1
                if sleep_time > 0:
                    time.sleep(sleep_time)

                resp = session.get(
                    f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,isp,org,as,asname,hosting",
                    timeout=5,
                )
                resp.raise_for_status()
                r = resp.json()
                if r.get("status") == "success":
                    full_info = f"{r.get('isp')} {r.get('org')} {r.get('as')} {r.get('asname')}".lower()
                    is_bad_hosting = any(word in full_info for word in BAD_HOSTING_KEYWORDS)
                    is_banned_pattern = any(pattern.lower() in full_info for pattern in BANNED_ASNAME_PATTERNS)
                    is_banned = is_bad_hosting or is_banned_pattern
                    if is_bad_hosting:
                        _inc_stat('banned_hosting')
                    if is_banned_pattern:
                        _inc_stat('banned_asname')
                    is_hosting_flag = r.get("hosting", False) and not is_bad_hosting
                    res = (r.get("countryCode"), "BANNED" if is_banned else is_hosting_flag)
                    with lock:
                        ip_cache[ip_str] = res
                    return res
            except (requests.RequestException, ValueError):
                pass

    return None, False


def apply_clean_params(config_link: str) -> str:
    """Удаляет fp/udp443 параметры и выставляет fp=random. Нормализует URL."""
    parts = config_link.split("#", 1)
    base = re.sub(r'[&?](?:fp|udp443)=[^&?#]+', '', parts[0])

    # Нормализация: убираем дублирование разделителей и слешей в пути
    # Сохраняем схему (://) нетронутой, нормализуем остальное
    scheme_match = re.match(r'^([a-zA-Z][a-zA-Z0-9+\-.]*://)', base)
    if scheme_match:
        scheme = scheme_match.group(1)
        rest = base[len(scheme):]
        # Убираем дублирующиеся & и ? внутри query
        rest = re.sub(r'\?&', '?', rest)
        rest = re.sub(r'&&+', '&', rest)
        base = scheme + rest
    else:
        base = re.sub(r'\?&', '?', base)
        base = re.sub(r'&&+', '&', base)

    sep = "&" if "?" in base else "?"
    base = f"{base}{sep}fp=random"

    return f"{base}#{parts[1]}" if len(parts) > 1 else base


def rename_config(link: str, country_code: str, index: int,
                  is_hosting=False, is_white_sni: bool = False) -> str:
    country_info = COUNTRY_MAP.get(country_code, {"full": country_code, "flag": "🌐"})
    tags = []
    if is_hosting is True:
        tags.append("HOST")
    if is_white_sni:
        tags.append("SNI-RU")
    tag_str = f" [{'|'.join(tags)}]" if tags else ""
    new_name = f"{country_info['flag']} {country_info['full']} — #{index}{tag_str}"
    return f"{link.split('#')[0]}#{requests.utils.quote(new_name)}"


def fetch_raw_configs(url: str) -> list[str]:
    for attempt in range(2):
        try:
            resp = session.get(url, timeout=7, verify=False).text
            if "://" not in resp[:50]:
                try:
                    resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
                except (ValueError, UnicodeDecodeError):
                    pass
            result = [l.strip() for l in re.findall(r'(?:vless|ssr|tuic|hysteria|hysteria2)://[^\s]+', resp)]
            if result:
                return result
            if attempt == 0:
                time.sleep(1.5)
        except requests.RequestException:
            if attempt == 0:
                time.sleep(1.5)
    return []


def get_sni_limit(is_white: bool, ip_cc: str) -> int:
    is_ru = (ip_cc == "RU")
    if is_white:
        return MAX_SAME_SNI_RU_RU if is_ru else MAX_SAME_SNI_RU
    return MAX_SAME_SNI_WORLD


def can_add_hosting(is_hosting, is_vlm2: bool) -> bool:
    if is_hosting is True:
        count = host_vlm2_count if is_vlm2 else host_vlm_count
        return count < MAX_HOST_CONFIGS
    return True


def can_add_sni_ru(entry: dict, is_vlm2: bool) -> bool:
    """Проверяет не превышен ли лимит MAX_TOTAL_SNI_RU для данного списка."""
    if not entry['white_sni']:
        return True
    # Во время повтора RU конфиги могут превышать лимит
    if sni_ru_retry_mode and entry['country'] == 'RU':
        return True
    current = sni_vlm2_count if is_vlm2 else sni_vlm_count
    return current < MAX_TOTAL_SNI_RU


def _trim_excess_sni_ru() -> None:
    """
    Если после повтора SNI-RU конфигов больше MAX_TOTAL_SNI_RU —
    удаляем случайные не-RU SNI-RU конфиги из обоих списков до лимита.
    """
    global sni_vlm_count, sni_vlm2_count, host_vlm_count, host_vlm2_count
    with lock:
        for results_list, is_vlm2 in [(vlm_results, False), (vlm2_results, True)]:
            sni_cnt = sni_vlm2_count if is_vlm2 else sni_vlm_count
            excess = sni_cnt - MAX_TOTAL_SNI_RU
            if excess <= 0:
                continue
            candidates = [r for r in results_list if r['white_sni'] and r['country'] != 'RU']
            to_remove = random.sample(candidates, min(excess, len(candidates)))
            for r in to_remove:
                results_list.remove(r)
                if is_vlm2:
                    sni_vlm2_count -= 1
                    if r['is_hosting'] is True: host_vlm2_count -= 1
                else:
                    sni_vlm_count -= 1
                    if r['is_hosting'] is True: host_vlm_count -= 1
            if to_remove:
                print(f"✂️  Удалено {len(to_remove)} лишних не-RU SNI-RU конфигов", flush=True)


def try_add_to_lists(entry: dict) -> bool:
    global ru_vlm_count, ru_vlm2_count, xhttp_count
    global host_vlm_count, host_vlm2_count, sni_vlm_count, sni_vlm2_count

    is_ru = (entry['country'] == 'RU')
    is_xhttp = entry['is_xhttp']
    is_hosting = entry['is_hosting']
    is_white = entry['white_sni']

    added_vlm = False
    added_vlm2 = False

    if is_xhttp:
        if is_ru:
            if ru_vlm2_count < MAX_RU_CONFIGS and xhttp_count < MAX_XHTTP and can_add_hosting(is_hosting, True) and can_add_sni_ru(entry, True):
                vlm2_results.append(entry)
                ru_vlm2_count += 1
                xhttp_count += 1
                if is_hosting is True: host_vlm2_count += 1
                if is_white: sni_vlm2_count += 1
                added_vlm2 = True
        else:
            if xhttp_count < MAX_XHTTP and len(vlm2_results) < MAX_CONFIGS and can_add_hosting(is_hosting, True) and can_add_sni_ru(entry, True):
                vlm2_results.append(entry)
                xhttp_count += 1
                if is_hosting is True: host_vlm2_count += 1
                if is_white: sni_vlm2_count += 1
                added_vlm2 = True
    else:
        if is_ru:
            if ru_vlm_count < MAX_RU_CONFIGS and len(vlm_results) < MAX_CONFIGS and can_add_hosting(is_hosting, False) and can_add_sni_ru(entry, False):
                vlm_results.append(entry)
                ru_vlm_count += 1
                if is_hosting is True: host_vlm_count += 1
                if is_white: sni_vlm_count += 1
                added_vlm = True
        elif len(vlm_results) < MAX_CONFIGS and can_add_hosting(is_hosting, False) and can_add_sni_ru(entry, False):
            vlm_results.append(entry)
            if is_hosting is True: host_vlm_count += 1
            if is_white: sni_vlm_count += 1
            added_vlm = True

        reserved_for_xhttp = max(0, MIN_XHTTP - xhttp_count)
        vlm2_space = MAX_CONFIGS - reserved_for_xhttp
        if is_ru:
            if ru_vlm2_count < MAX_RU_CONFIGS and len(vlm2_results) < vlm2_space and can_add_hosting(is_hosting, True) and can_add_sni_ru(entry, True):
                vlm2_results.append(entry)
                ru_vlm2_count += 1
                if is_hosting is True: host_vlm2_count += 1
                if is_white: sni_vlm2_count += 1
                added_vlm2 = True
        elif len(vlm2_results) < vlm2_space and can_add_hosting(is_hosting, True) and can_add_sni_ru(entry, True):
            vlm2_results.append(entry)
            if is_hosting is True: host_vlm2_count += 1
            if is_white: sni_vlm2_count += 1
            added_vlm2 = True

    return added_vlm or added_vlm2


def check_completion() -> bool:
    vlm_done = (ru_vlm_count >= MIN_RU_CONFIGS and len(vlm_results) >= MAX_CONFIGS)
    vlm2_done = (ru_vlm2_count >= MIN_RU_CONFIGS and xhttp_count >= MIN_XHTTP and len(vlm2_results) >= MAX_CONFIGS)
    if vlm_done and vlm2_done:
        stop_event.set()
        sni_ru_done_event.set()
        return True
    # Проверяем достигнуты ли цели SNI-RU фазы
    ru_vlm_ok   = ru_vlm_count  >= MIN_RU_CONFIGS
    ru_vlm2_ok  = ru_vlm2_count >= MIN_RU_CONFIGS
    sni_vlm_ok  = sni_vlm_count  >= MAX_TOTAL_SNI_RU
    sni_vlm2_ok = sni_vlm2_count >= MAX_TOTAL_SNI_RU
    if ru_vlm_ok and ru_vlm2_ok and sni_vlm_ok and sni_vlm2_ok:
        sni_ru_done_event.set()
    return False



def _get_config_key(host: str, port: int, sni: str, cid: str) -> str:
    """Возвращает ключ конфига для кэша checked_configs."""
    return f"{host}:{port}:{cid}:{sni}"

def validate(config: str, is_priority: bool, is_white: bool) -> None:
    if stop_event.is_set():
        _inc_stat('stopped')
        return
    # Во время фазы SNI-RU останавливаемся по sni_ru_done_event
    if is_white and sni_ru_done_event.is_set():
        return

    if is_technically_broken(config):
        _inc_stat('broken')
        return

    host, port, sni, cid = get_config_details(config)
    if not host or not sni:
        _inc_stat('no_details')
        return

    # Проверка кэша уже проверенных конфигов
    config_key = _get_config_key(host, port, sni, cid)
    with lock:
        if config_key in checked_configs:
            _inc_stat('checked_cache')
            return

    if host in failed_ips:
        _inc_stat('failed_ip_cache')
        return

    # ── СЛОЙ 1: фильтр РКН (до пинга — быстро) ──────────────────────────────
    if is_blocked_in_ru(host):
        _inc_stat('blocked_rkn')
        return

    is_xhttp = "xhttp" in config.lower()
    subnet = ".".join(host.split(".")[:3])
    subnet16 = ".".join(host.split(".")[:2])

    with lock:
        if host in seen_ips:
            _inc_stat('duplicate_ip')
            return

        if (sni in sni_domains) != is_white:
            _inc_stat('sni_mismatch')
            return

        if any(exc in sni for exc in EXCLUDED_SNI_DOMAINS):
            _inc_stat('excluded_sni')
            return

        if subnet_counts[subnet] >= MAX_PER_SUBNET:
            _inc_stat('subnet_limit')
            return

        if id_counts[cid] >= MAX_PER_ID:
            _inc_stat('id_limit')
            return

    # Первый пинг
    p1 = fast_ping(host, port, sni)
    initial_max_p = MAX_WORLD_PING_XHTTP if is_xhttp else MAX_WORLD_PING
    if not p1 or p1 > initial_max_p:
        with lock:
            failed_subnets[subnet] += 1
            failed_ips.add(host)
        _inc_stat('first_ping_failed')
        return

    # Проверка ISP
    ip_cc, ip_h_stat = check_isp_info(host)
    if not ip_cc or ip_h_stat == "BANNED" or stop_event.is_set():
        with lock:
            checked_configs.add(config_key)
        _inc_stat('isp_banned')
        return
    # RU принимаем только если SNI-RU
    if ip_cc == "RU" and not is_white:
        with lock:
            checked_configs.add(config_key)
        _inc_stat('ru_without_white_sni')
        return

    # Проверка лимита подсети /16
    config_type = get_config_type(ip_cc, is_white)
    subnet16_limit = get_subnet16_limit(config_type)

    subnet16_reserved = False
    with lock:
        if subnet16_counts[subnet16][config_type] >= subnet16_limit:
            _inc_stat('subnet16_limit')
            return
        subnet16_counts[subnet16][config_type] += 1
        subnet16_reserved = True

    # Атомарная резервация SNI
    sni_reserved = False
    with lock:
        sni_limit = get_sni_limit(is_white, ip_cc)
        if sni_usage_counts[sni] >= sni_limit:
            _inc_stat('sni_limit')
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
        with lock:
            checked_configs.add(config_key)
        return

    # ── XRAY-ТЕСТ: реальная проверка туннеля ─────────────────────────────────
    if not xray_test(config, is_ru=is_ru):
        if sni_reserved:
            with lock:
                sni_usage_counts[sni] -= 1
        if subnet16_reserved:
            with lock:
                subnet16_counts[subnet16][config_type] -= 1
        with lock:
            checked_configs.add(config_key)
        return

    # Финальное добавление
    with lock:
        if host in seen_ips:
            if sni_reserved:
                sni_usage_counts[sni] -= 1
            if subnet16_reserved:
                subnet16_counts[subnet16][config_type] -= 1
            _inc_stat('race_duplicate')
            return

        if failed_subnets[subnet] >= MAX_FAILED_PER_SUBNET:
            if sni_reserved:
                sni_usage_counts[sni] -= 1
            if subnet16_reserved:
                subnet16_counts[subnet16][config_type] -= 1
            _inc_stat('subnet_banned')
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
            _inc_stat('added')
            if is_white:
                if is_priority:
                    _inc_stat('sni_ru_from_extra')
                else:
                    _inc_stat('sni_ru_from_std')
            check_completion()
        else:
            sni_usage_counts[sni] -= 1
            if subnet16_reserved:
                subnet16_counts[subnet16][config_type] -= 1
            _inc_stat('not_added')


def fetch_group_data(urls: list[str]) -> list[str]:
    raw: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(fetch_raw_configs, u) for u in set(urls)]
        for f in concurrent.futures.as_completed(futures):
            raw.extend(f.result())
    unique = list(set(raw))
    random.shuffle(unique)
    return unique


def finalize_list(results: list[dict], is_vlm2: bool = False) -> list[str]:
    all_ru_sni = sorted(
        [r for r in results if r['country'] == 'RU' and r['white_sni']],
        key=lambda x: x['ping'],
    )
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

    # Используем deque для эффективного popleft() вместо pop(0)
    from collections import deque
    xhttp_dq = deque(xhttp_bucket)
    non_ru_dq = deque(non_ru_sni_configs)
    ru_sni_dq = deque(ru_sni_configs)

    final = list(top_fixed)
    final_links = {r['link'] for r in final}
    current_ru_sni_total = len(top_fixed)

    while len(final) < MAX_CONFIGS:
        added_any = False

        if is_vlm2 and xhttp_dq and len(final) == len(top_fixed):
            count = 0
            while count < INTERLEAVE_STEP and len(final) < MAX_CONFIGS and xhttp_dq:
                config = xhttp_dq.popleft()
                if config['link'] not in final_links:
                    final.append(config)
                    final_links.add(config['link'])
                    count += 1
                    added_any = True

        count = 0
        while count < INTERLEAVE_STEP and len(final) < MAX_CONFIGS and non_ru_dq:
            config = non_ru_dq.popleft()
            if config['link'] not in final_links:
                final.append(config)
                final_links.add(config['link'])
                count += 1
                added_any = True

        count = 0
        while count < INTERLEAVE_STEP and len(final) < MAX_CONFIGS and ru_sni_dq:
            if current_ru_sni_total >= MAX_TOTAL_SNI_RU:
                break
            config = ru_sni_dq.popleft()
            if config['link'] not in final_links:
                final.append(config)
                final_links.add(config['link'])
                count += 1
                added_any = True
                current_ru_sni_total += 1

        if not added_any:
            break

    speed_rating = {
        r['link']: rank + 1
        for rank, r in enumerate(sorted(final, key=lambda x: x['ping']))
    }
    return [
        rename_config(r['link'], r['country'], speed_rating[r['link']], r['is_hosting'], r['white_sni'])
        for r in final
    ]


def print_statistics() -> None:
    with stats_lock:
        s = defaultdict(int, stats)
    with lock:
        vlm_len = len(vlm_results)
        vlm2_len = len(vlm2_results)
        _ru_vlm = ru_vlm_count
        _ru_vlm2 = ru_vlm2_count
        _xhttp = xhttp_count
        vlm_host  = host_vlm_count
        vlm2_host = host_vlm2_count
    with stats_lock:
        _api = api_calls_count

    with stats_lock:
        _sni_extra = stats['sni_ru_from_extra']
        _sni_std   = stats['sni_ru_from_std']

    print("\n--- 📊 СТАТИСТИКА ---", flush=True)
    print(f"Добавлено: {s['added']}", flush=True)

    print("\n[Локальные проверки]", flush=True)
    print(f"Технически битые: {s['broken']}", flush=True)
    print(f"Без деталей: {s['no_details']}", flush=True)
    print(f"Кэш проверенных: {s['checked_cache']}", flush=True)
    print(f"Заблокировано РКН: {s['blocked_rkn']}", flush=True)
    print(f"Дубликаты IP: {s['duplicate_ip']}", flush=True)
    print(f"Кэш неудачных IP: {s['failed_ip_cache']}", flush=True)
    print(f"Исключён по SNI домену: {s['excluded_sni']}", flush=True)
    print(f"Лимиты подсети: {s['subnet_limit']}", flush=True)

    print("\n[Сетевые проверки]", flush=True)
    print(f"Первый пинг провален: {s['first_ping_failed']}", flush=True)
    print(f"Запросов к ip-api: {_api} (кэш попаданий: {s['duplicate_ip'] + s['race_duplicate']})", flush=True)
    print(f"ISP забанен: {s['isp_banned']}", flush=True)
    print(f"Плохой хостинг (BAD_HOSTING): {s['banned_hosting']}", flush=True)
    print(f"Забанен по ASN паттерну: {s['banned_asname']}", flush=True)
    print(f"Пинг вне диапазона: {s['ping_out_of_range']}", flush=True)
    print(f"Jitter провален: {s['jitter_failed']}", flush=True)
    print(f"Лимиты SNI: {s['sni_limit']}", flush=True)
    print(f"Подсеть забанена: {s['subnet_banned']}", flush=True)
    print(f"Не добавлено (нет места): {s['not_added']}", flush=True)
    print(f"Не прошло Xray-тест: {s['xray_failed']}", flush=True)

    print(f"\n[Итог]", flush=True)
    print(f"VLM: {vlm_len} (RU: {_ru_vlm}, HOST: {vlm_host})", flush=True)
    print(f"VLM2: {vlm2_len} (RU: {_ru_vlm2}, XHTTP: {_xhttp}, HOST: {vlm2_host})", flush=True)
    print(f"SNI-RU из extra: {_sni_extra}, из std: {_sni_std}", flush=True)


def main() -> None:
    global sni_domains, xray_available

    start_total = time.perf_counter()
    print(f"--- 🟢 ЗАПУСК [{offset}] ---", flush=True)

    # Проверяем наличие Xray
    try:
        result = subprocess.run(
            [XRAY_BINARY, "version"],
            capture_output=True,
            timeout=XRAY_PROCESS_TIMEOUT,
        )
        xray_available = result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        xray_available = False
    print(
        f"{'✅' if xray_available else '⚠️ '} Xray: "
        f"{'доступен' if xray_available else 'не найден, тест отключён'}",
        flush=True,
    )

    sni_domains = set()
    extra_urls, std_urls, gh_repo = [], [], None

    try:
        gh_repo = Github(auth=Auth.Token(GITHUB_TOKEN)).get_repo(REPO_NAME)
    except Exception as e:
        print(f"⚠️  GitHub недоступен: {e}", flush=True)

    try:
        src_text = session.get(REMOTE_SOURCE_URL, timeout=10).text

        def get_list(var: str) -> list[str]:
            m = re.search(rf'{var}\s*=\s*\[(.*?)\]', src_text, re.S | re.I)
            return re.findall(r'["\']([^"\']+)["\']', m.group(1)) if m else []

        extra_urls, std_urls = get_list("EXTRA_URLS_FOR_26"), get_list("URLS")
        sni_domains.update(s.lower() for s in get_list("SNI_DOMAINS"))

        sec_text = session.get(SECONDARY_WHITELIST_URL, timeout=10).text
        sni_domains.update(line.strip().lower() for line in sec_text.splitlines() if line.strip())
    except requests.RequestException as e:
        print(f"⚠️  Не удалось загрузить источники: {e}", flush=True)

    print(f"Загружено SNI доменов: {len(sni_domains)}", flush=True)
    print(f"Extra URLs: {len(extra_urls)}, Standard URLs: {len(std_urls)}", flush=True)

    load_ru_blocklist()

    raw_extra, raw_std = fetch_group_data(extra_urls), fetch_group_data(std_urls)
    print(f"Уникальных конфигов: Extra={len(raw_extra)}, Std={len(raw_std)}", flush=True)

    def _has_white_sni(config: str) -> bool:
        """Возвращает True если SNI конфига есть в белом списке."""
        s_m = re.search(r'[?&]sni=([^&#\s]*)', config, re.I)
        if not s_m:
            return False
        return s_m.group(1).lower() in sni_domains

    raw_nonwhite = list(set(c for c in raw_extra + raw_std if not _has_white_sni(c)))
    random.shuffle(raw_nonwhite)
    print(f"Не SNI-RU (объединённая корзина): {len(raw_nonwhite)}", flush=True)

    def _sni_ru_targets_met() -> bool:
        """Все условия по SNI-RU выполнены — повтор не нужен."""
        with lock:
            ru_vlm_ok   = ru_vlm_count  >= MIN_RU_CONFIGS
            ru_vlm2_ok  = ru_vlm2_count >= MIN_RU_CONFIGS
            sni_vlm_ok  = sni_vlm_count  >= MAX_TOTAL_SNI_RU
            sni_vlm2_ok = sni_vlm2_count >= MAX_TOTAL_SNI_RU
        return ru_vlm_ok and ru_vlm2_ok and sni_vlm_ok and sni_vlm2_ok

    def _run_sni_ru_phase(extra: list, std: list) -> None:
        """Прогоняет SNI-RU группы, останавливается по sni_ru_done_event или stop_event."""
        for group, priority, white in [(extra, True, True), (std, False, True)]:
            if stop_event.is_set() or sni_ru_done_event.is_set():
                break
            workers = min(len(group), 40) if group else 1
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as v:
                for c in group:
                    if stop_event.is_set() or sni_ru_done_event.is_set():
                        break
                    v.submit(validate, c, priority, white)

    def _run_non_sni_ru_phase() -> None:
        """Запускает NON SNI-RU поиск."""
        if stop_event.is_set():
            return
        workers = min(len(raw_nonwhite), 40) if raw_nonwhite else 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as v:
            for c in raw_nonwhite:
                if stop_event.is_set():
                    break
                v.submit(validate, c, True, False)

    def _replace_others_with_sni_ru(new_entries: list) -> None:
        """
        Заменяет случайные others конфиги на новые RU+SNI-RU.
        Others кандидаты — только те у которых одинаковый ключ в обоих списках.
        """
        global ru_vlm_count, ru_vlm2_count
        if not new_entries:
            return
        with lock:
            # Находим ключи others которые есть в ОБОИХ списках
            def get_key(r):
                m = re.search(r'@([^:/?#\s]+):(\d+)', r['link'])
                s = re.search(r'[?&]sni=([^&#\s]*)', r['link'], re.I)
                cid = re.search(r'://([^@]+)@', r['link'])
                if not m:
                    return None
                return f"{m.group(1)}:{m.group(2)}:{cid.group(1) if cid else ''}:{s.group(1).lower() if s else ''}"

            vlm_others_keys  = {get_key(r): r for r in vlm_results  if not r['white_sni'] and get_key(r)}
            vlm2_others_keys = {get_key(r): r for r in vlm2_results if not r['white_sni'] and get_key(r)}
            common_keys = list(set(vlm_others_keys.keys()) & set(vlm2_others_keys.keys()))

            to_remove = min(len(new_entries), len(common_keys))
            if to_remove == 0:
                print("⚠️  Нет общих others для замены", flush=True)
                return

            keys_to_remove = random.sample(common_keys, to_remove)
            entries_to_add = new_entries[:to_remove]

            # Удаляем из обоих списков
            for k in keys_to_remove:
                r_vlm  = vlm_others_keys[k]
                r_vlm2 = vlm2_others_keys[k]
                if r_vlm  in vlm_results:  vlm_results.remove(r_vlm)
                if r_vlm2 in vlm2_results: vlm2_results.remove(r_vlm2)

            # Добавляем новые SNI-RU конфиги
            for entry in entries_to_add:
                vlm_results.append(entry)
                vlm2_results.append(entry)
                if entry['country'] == 'RU':
                    ru_vlm_count  += 1
                    ru_vlm2_count += 1

            print(f"🔄 Заменено {to_remove} others на RU+SNI-RU конфиги", flush=True)

    # --- Фаза 1: SNI-RU конфиги ---
    _run_sni_ru_phase(raw_extra, raw_std)

    # --- Повтор если не добрали ---
    for attempt in range(1, RU_RETRY_MAX + 1):
        if stop_event.is_set():
            break
        if _sni_ru_targets_met():
            break

        with lock:
            _ru_vlm   = ru_vlm_count
            _ru_vlm2  = ru_vlm2_count
            _sni_vlm  = sni_vlm_count
            _sni_vlm2 = sni_vlm2_count
        print(
            f"⚠️  SNI-RU не добран ("
            f"vlm: RU={_ru_vlm}/{MIN_RU_CONFIGS}, SNI={_sni_vlm}/{MAX_TOTAL_SNI_RU} | "
            f"vlm2: RU={_ru_vlm2}/{MIN_RU_CONFIGS}, SNI={_sni_vlm2}/{MAX_TOTAL_SNI_RU}). "
            f"Попытка {attempt}/{RU_RETRY_MAX}",
            flush=True,
        )

        # --- Запускаем NON SNI-RU пока ждём повтор ---
        print(f"🔍 Запускаем поиск остальных конфигов пока ждём {RU_RETRY_WAIT}с...", flush=True)
        non_sni_thread = threading.Thread(target=_run_non_sni_ru_phase, daemon=True)
        non_sni_thread.start()
        time.sleep(RU_RETRY_WAIT)
        # Ждём завершения NON SNI-RU если ещё не закончил
        non_sni_thread.join()

        _partial_cache_reset()

        raw_extra_retry = fetch_group_data(extra_urls)
        raw_std_retry   = fetch_group_data(std_urls)
        print(
            f"🔁 Повтор SNI-RU: Extra={len(raw_extra_retry)}, Std={len(raw_std_retry)}",
            flush=True,
        )

        # Собираем новые SNI-RU конфиги отдельно
        new_sni_ru_found = []
        sni_ru_retry_mode = True

        def _collect_sni_ru(config, priority, white):
            """Валидирует конфиг и если принят — добавляет в new_sni_ru_found."""
            host_m = re.search(r'@([^:/?#\s]+):', config)
            if not host_m:
                return
            # Временно убираем из seen_ips чтобы дать шанс — нет, просто проверяем
            # через validate, но перехватываем добавление отдельно
            pass

        # Сбрасываем sni_ru_done_event
        sni_ru_done_event.clear()

        # Временно подменяем vlm_results/vlm2_results на временные списки
        # чтобы собрать только новые SNI-RU конфиги
        temp_vlm  = []
        temp_vlm2 = []

        with lock:
            orig_vlm_len  = len(vlm_results)
            orig_vlm2_len = len(vlm2_results)
            # Освобождаем место — убираем лимит на время повтора
            # (sni_ru_retry_mode уже True — can_add_sni_ru пропустит RU)

        sni_ru_retry_mode = True
        _run_sni_ru_phase(raw_extra_retry, raw_std_retry)
        sni_ru_retry_mode = False

        # Собираем что добавилось за время повтора
        with lock:
            new_sni_ru_found = [
                r for r in vlm_results[orig_vlm_len:]
                if r['white_sni']
            ]

        # Убираем лишние не-RU SNI-RU если превысили лимит
        _trim_excess_sni_ru()

        # Заменяем others на найденные SNI-RU если списки уже полные
        with lock:
            vlm_full  = len(vlm_results)  >= MAX_CONFIGS
            vlm2_full = len(vlm2_results) >= MAX_CONFIGS
        if (vlm_full or vlm2_full) and new_sni_ru_found:
            _replace_others_with_sni_ru(new_sni_ru_found)

        with lock:
            _ru_vlm   = ru_vlm_count
            _ru_vlm2  = ru_vlm2_count
            _sni_vlm  = sni_vlm_count
            _sni_vlm2 = sni_vlm2_count
        print(
            f"📊 После попытки {attempt}: "
            f"vlm RU={_ru_vlm}, SNI={_sni_vlm} | "
            f"vlm2 RU={_ru_vlm2}, SNI={_sni_vlm2}",
            flush=True,
        )

    # Если списки ещё не заполнены — запускаем NON SNI-RU
    with lock:
        needs_more = len(vlm_results) < MAX_CONFIGS or len(vlm2_results) < MAX_CONFIGS
    if needs_more and not stop_event.is_set():
        print("🔍 Добираем остальные конфиги...", flush=True)
        _run_non_sni_ru_phase()

    print_statistics()

    if gh_repo:
        for fn, res in [(FILENAME_VLM, vlm_results), (FILENAME_VLM2, vlm2_results)]:
            output = finalize_list(res, is_vlm2=(fn == FILENAME_VLM2))
            path, content = f"githubmirror/{fn}", "\n".join(output)
            try:
                sha = gh_repo.get_contents(path).sha
                gh_repo.update_file(path, f"🚀 {fn} | {len(output)} | {offset}", content, sha)
                print(f"✅ Обновлен {fn}: {len(output)} конфигов", flush=True)
            except Exception:
                try:
                    gh_repo.create_file(path, f"🚀 {fn} | {len(output)} | {offset}", content)
                    print(f"✅ Создан {fn}: {len(output)} конфигов", flush=True)
                except Exception as e:
                    print(f"❌ Ошибка записи {fn}: {e}", flush=True)

    print(f"--- 🏁 ГОТОВО за {time.perf_counter() - start_total:.1f}с ---")


if __name__ == "__main__":
    main()
