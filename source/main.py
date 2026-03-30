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
FILENAME_IP_CACHE     = "ip_cache"     # кэш обычных IP
FILENAME_DOMAIN_CACHE = "domain_cache" # кэш доменных конфигов (вид 1)
FILENAME_WS_CACHE     = "ws_cache"     # кэш WS конфигов (вид 2)
IP_CACHE_TTL_DAYS     = 3              # TTL для обычных IP (дней)
DOMAIN_CACHE_TTL_DAYS = 3              # TTL для доменных конфигов (дней)
WS_CACHE_TTL_DAYS     = 1              # TTL для WS конфигов (дней)

# --- ЛИМИТЫ БРОНИРОВАНИЯ ---
MIN_XHTTP = 0
MAX_XHTTP = 5
MIN_RU_CONFIGS = 3
MAX_RU_CONFIGS = 6
MIN_HOST_CONFIGS = 0
MAX_HOST_NOWS_CONFIGS = 7   # лимит HOST конфигов (обычных)
MAX_WS_HOST_CONFIGS   = 2   # лимит WS конфигов с host= параметром
MAX_DOMAIN_HOST_CONFIGS = 6  # лимит конфигов вид 1 (домен вместо IPv4)
MAX_DOMAIN_MID_CONFIGS  = 2  # лимит конфигов с одинаковой средней частью домена
MAX_FAILED_PER_DOMAIN   = 6  # максимум провалов пинга для одного домен:порт

INTERLEAVE_STEP = 3
EXCLUDED_SNI_DOMAINS = ["userapi", "splitter.wb.ru"]
BAD_HOSTING_KEYWORDS = [
    "cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google",
    "microsoft", "ovh", "linode", "oracle", "leaseweb",
    "m247", "akamai",
]

HOST_TAG_KEYWORDS = [
    # ISP/провайдеры которые помечаются тегом HOST но не баниятся
    "vps", "host", "baykov", "dataforest", "work", "servers"
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

BAD_HOSTING_KEYWORDS_WS = [
    # Слова для бана WS конфигов с host= (cloudflare здесь НЕ добавляем)
    "hetzner", "digitalocean", "vultr", "amazon", "google",
    "microsoft", "ovh", "linode", "oracle", "leaseweb",
    "m247", "akamai",
]

# Включатели/выключатели фильтров
BAD_HOSTING_ENABLED    = True   # банить плохой хостинг (обычные конфиги)
BAD_HOSTING_WS_ENABLED = True   # банить плохой хостинг (WS конфиги с host=)
BANNED_ASNAME_ENABLED  = False  # банить по ASN паттернам

# Настройки повтора SNI-RU
RU_RETRY_ENABLED    = False # включить/выключить повтор SNI-RU
RU_RETRY_WAIT       = 240  # секунд ожидания перед каждой повторной попыткой
RU_RETRY_MAX        = 1    # максимум попыток добора SNI-RU
CACHE_RESET_MODE    = 1    # 0 - не очищать, 1 - очищать наполовину, 2 - очищать полностью

# Настройки конфигураций
MAX_CONFIGS = 50
MAX_TOTAL_SNI_RU = MAX_CONFIGS // 2
MAX_TOP_RU_SNI = MAX_RU_CONFIGS

MAX_PER_SUBNET = 3
MAX_PER_SUBNET16_RU_SNI = 2
MAX_PER_SUBNET16_NONRU_SNI = 6
MAX_PER_SUBNET16_OTHERS = 9

MAX_PER_ID = 6
MAX_FAILED_PER_SUBNET = 6

# Лимиты на повторение SNI
MAX_SAME_SNI_RU_RU = 2  # RU IP + white SNI
MAX_SAME_SNI_RU = 8     # Не-RU IP + white SNI
MAX_SAME_SNI_WORLD = 5  # Любой IP + не-white SNI

MIN_RU_PING, MAX_RU_PING = 50.0, 2000.0
MIN_WORLD_PING, MAX_WORLD_PING = 10.0, 2000.0

# Расширенные лимиты для XHTTP
MAX_RU_PING_XHTTP = MAX_RU_PING + 120
MAX_WORLD_PING_XHTTP = MAX_WORLD_PING + 120

# Таймауты (секунды)
FAST_PING_TIMEOUT = 2.0

# Настройки мониторинга сети
NETWORK_FAIL_THRESHOLD = 5   # сколько последовательных провалов пинга считать падением сети
NETWORK_CHECK_INTERVAL = 5  # секунд между проверками восстановления сети
NETWORK_MAX_RETRIES = 4      # максимум попыток проверки восстановления сети

# Настройки полного анализа пинга (TCP)
MAX_JITTER = 150
MAX_JITTER_RATIO = 0.4
FULL_PING_PAUSE = 0.15
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
XRAY_HTTP_TIMEOUT = 2.5   # секунд на один HTTP запрос через туннель
XRAY_HTTP_ATTEMPTS = 3    # количество HTTP замеров для подсчёта пинга и jitter
XRAY_HTTP_PAUSE = 0.15    # пауза между HTTP замерами (секунд)
XRAY_STARTUP_CHECK_INTERVAL = 0.1  # интервал проверки готовности xray (секунд)
XRAY_MAX_PARALLEL = 4     # максимум одновременных xray-процессов
XRAY_PORT_BASE = 10000    # стартовый порт для SOCKS5, каждый тред берёт свой
XRAY_PROCESS_TIMEOUT = 5  # таймаут на запуск xray version

# Настройки теста скорости
XRAY_SPEED_TEST_URL = "https://speed.cloudflare.com/__down?bytes=5000000"  # 5MB файл
XRAY_SPEED_TEST_DURATION = 3.0  # секунд на скачивание
XRAY_SPEED_MIN_MBPS = 5.0       # минимальная скорость Мбит/с (0 = не фильтровать)

# Лимиты пинга через xray туннель (via proxy get)
MIN_XRAY_PING = 50.0      # минимальный пинг через туннель (мс)
MAX_XRAY_PING = 2500.0    # максимальный пинг через туннель (мс)
MAX_XRAY_JITTER = 100     # максимальный jitter через туннель (мс)
MAX_XRAY_JITTER_RATIO = 0.3  # максимальный jitter как доля от среднего

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
    "KE": {"aliases": ["KENYA", "КЕНИЯ", "🇰🇪"], "full": "Kenya", "flag": "🇰🇪"},
    "AM": {"aliases": ["ARMENIA", "АРМЕНИЯ", "🇦🇲"], "full": "Armenia", "flag": "🇦🇲"},
    "CY": {"aliases": ["CYPRUS", "КИПР", "🇨🇾"], "full": "Cyprus", "flag": "🇨🇾"},
    "BE": {"aliases": ["BELGIUM", "БЕЛЬГИЯ", "🇧🇪"], "full": "Belgium", "flag": "🇧🇪"},
    "IN": {"aliases": ["INDIA", "ИНДИЯ", "🇮🇳"], "full": "India", "flag": "🇮🇳"},
    "IL": {"aliases": ["ISRAEL", "ИЗРАИЛЬ", "🇮🇱"], "full": "Izrael", "flag": "🇮🇱"},
    "BA": {"aliases": ["BOSNIA AND HERZEGOVINA", "БОСНИЯ И ГЕРЦЕГОВИНА", "🇧🇦"], "full": "B&H", "flag": "🇧🇦"},
    "UY": {"aliases": ["URUGUAY", "УРУГВАЙ", "🇺🇾"], "full": "Uruguay", "flag": "🇺🇾"},
    "TW": {"aliases": ["TAIWAN", "ТАЙВАНЬ", "🇹🇼"], "full": "Taiwan", "flag": "🇹🇼"},
    "PK": {"aliases": ["PAKISTAN", "ПАКИСТАН", "🇵🇰"], "full": "Pakistan", "flag": "🇵🇰"},
    "IQ": {"aliases": ["IRAQ", "ИРАК", "🇮🇶"], "full": "Iraq", "flag": "🇮🇶"},
}

# --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ---
lock = threading.Lock()
stats_lock = threading.Lock()   # отдельный лок для счётчиков статистики
api_semaphore = threading.Semaphore(3)
stop_event = threading.Event()
sni_ru_done_event = threading.Event()  # сигнал завершения фазы SNI-RU

# Кэши и счетчики (защищены основным lock)
ip_cache = {}
seen_configs = set()  # базовые части ссылок для подсчёта уникальных конфигов
failed_ips = set()
failed_domain_counts = defaultdict(int)  # счётчик провалов по домен:порт
checked_configs_raw = set()  # (config_base, is_white) для быстрой проверки повторов
failed_subnets = defaultdict(int)
seen_ips = set()
subnet_counts = defaultdict(int)
subnet16_counts = defaultdict(lambda: defaultdict(int))
id_counts = defaultdict(int)
sni_usage_counts = defaultdict(int)

# Флаг режима повтора SNI-RU
sni_ru_retry_mode = False

# Буфер вытесненных не-RU SNI-RU конфигов для динамического резервирования
non_ru_sni_buffer_vlm  = []
non_ru_sni_buffer_vlm2 = []

# Счетчики для vlm/vlm2 (защищены основным lock)
ru_vlm_count = 0
ru_vlm2_count = 0
xhttp_count = 0
host_vlm_count = 0      # количество HOST конфигов в vlm
host_vlm2_count = 0     # количество HOST конфигов в vlm2
ws_host_vlm_count = 0      # количество WS host= конфигов в vlm
ws_host_vlm2_count = 0     # количество WS host= конфигов в vlm2
domain_host_vlm_count = 0  # количество domain host конфигов в vlm
domain_host_vlm2_count = 0 # количество domain host конфигов в vlm2
domain_mid_counts = defaultdict(int)  # счётчик по средней части домена
sni_vlm_count = 0    # количество white_sni конфигов в vlm
sni_vlm2_count = 0   # количество white_sni конфигов в vlm2

vlm_results = []
vlm2_results = []

# Токен-бакет для rate limiting ip-api
_api_token_lock = threading.Lock()
_api_last_token_time = 0.0  # время последней выдачи токена
_api_retry_after = 0.0      # время до которого нельзя делать запросы (429)

# Статистика для отладки (защищена stats_lock)
stats = defaultdict(int)
api_calls_count = 0

# Персистентный кэши из GitHub
persistent_ip_cache: dict     = {}  # обычные IP
persistent_domain_cache: dict = {}  # доменные конфиги (вид 1)
persistent_ws_cache: dict     = {}  # WS конфиги (вид 2)

# Кэш резолвинга доменных хостов (домен -> IP)
_domain_host_cache: dict = {}
_domain_host_lock = threading.Lock()

# Мониторинг состояния сети
network_down = False           # флаг падения сети
network_fail_counter = 0       # счётчик последовательных провалов
network_lock = threading.Lock()

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
    global failed_ips, failed_domain_counts, checked_configs_raw

    if CACHE_RESET_MODE == 0:
        print("🔄 Сброс кэшей пропущен (CACHE_RESET_MODE=0)", flush=True)
        return

    with lock:
        working_ip_ports = set()
        for r in vlm_results + vlm2_results:
            m = re.search(r'@([^:/?#\s]+):(\d+)', r['link'])
            if m:
                working_ip_ports.add(f"{m.group(1)}:{m.group(2)}")
        non_working_failed = list(failed_ips - working_ip_ports)
        working_raw = set()
        for r in vlm_results + vlm2_results:
            base = r['link'].split('#')[0]
            working_raw.add((base, True))
            working_raw.add((base, False))
        non_working_raw = list({k for k in checked_configs_raw if k not in working_raw})

        if CACHE_RESET_MODE == 1:
            failed_ips -= set(random.sample(non_working_failed, len(non_working_failed) // 2))
            for k in random.sample(non_working_raw, len(non_working_raw) // 2):
                checked_configs_raw.discard(k)
            for k in list(failed_domain_counts.keys()):
                failed_domain_counts[k] = failed_domain_counts[k] // 2
            print("🔄 Кэши сброшены (failed_ips и checked_configs_raw наполовину)", flush=True)
        elif CACHE_RESET_MODE == 2:
            failed_ips -= set(non_working_failed)
            checked_configs_raw -= set(non_working_raw)
            failed_domain_counts.clear()
            print("🔄 Кэши сброшены (failed_ips и checked_configs_raw полностью)", flush=True)


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


def _measure_speed(proxies: dict) -> float:
    """Измеряет скорость через туннель. Скачивает XRAY_SPEED_TEST_DURATION секунд,
    возвращает скорость в Мбит/с."""
    try:
        start = time.perf_counter()
        total_bytes = 0
        with requests.get(
            XRAY_SPEED_TEST_URL,
            proxies=proxies,
            timeout=XRAY_SPEED_TEST_DURATION + 2,
            stream=True,
            verify=False,
        ) as r:
            for chunk in r.iter_content(chunk_size=8192):
                total_bytes += len(chunk)
                if time.perf_counter() - start >= XRAY_SPEED_TEST_DURATION:
                    break
        elapsed = time.perf_counter() - start
        if elapsed > 0 and total_bytes > 0:
            mbps = (total_bytes * 8) / (elapsed * 1_000_000)
            return round(mbps, 2)
    except Exception:
        pass
    return 0.0


def xray_test(config_link: str, is_ru: bool = False, fetch_geo: bool = False) -> tuple | None:
    """
    Запускает Xray с конфигом, делает XRAY_HTTP_ATTEMPTS HTTP запросов через туннель.
    Если fetch_geo=True — дополнительно запрашивает ip-api через туннель.
    Возвращает (avg_ping, jitter) или (avg_ping, jitter, geo_data).
    Возвращает None если туннель не работает.
    Если xray недоступен — возвращает (0, 0).
    """
    if not xray_available:
        return (0, 0)

    socks_port = _get_xray_port()
    xray_cfg = _build_xray_config(config_link, socks_port)
    if not xray_cfg:
        return (0, 0)

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

            # Умное ожидание: проверяем готовность SOCKS5 порта
            deadline = time.perf_counter() + XRAY_STARTUP_WAIT
            xray_ready = False
            while time.perf_counter() < deadline:
                if proc.poll() is not None:
                    _inc_stat('xray_failed')
                    return None
                try:
                    with socket.create_connection(("127.0.0.1", socks_port), timeout=0.1):
                        xray_ready = True
                        break
                except OSError:
                    time.sleep(XRAY_STARTUP_CHECK_INTERVAL)

            if not xray_ready:
                _inc_stat('xray_failed')
                return None

            proxies = {
                "http":  f"socks5://127.0.0.1:{socks_port}",
                "https": f"socks5://127.0.0.1:{socks_port}",
            }
            test_url = XRAY_TEST_URL_RU if is_ru else XRAY_TEST_URL_WORLD

            # Делаем XRAY_HTTP_ATTEMPTS замеров
            pings = []
            for i in range(XRAY_HTTP_ATTEMPTS):
                if i > 0:
                    time.sleep(XRAY_HTTP_PAUSE)
                try:
                    start = time.perf_counter()
                    r = requests.get(
                        test_url,
                        proxies=proxies,
                        timeout=XRAY_HTTP_TIMEOUT,
                        verify=False,
                    )
                    elapsed = int((time.perf_counter() - start) * 1000)
                    if r.status_code in (200, 204):
                        pings.append(elapsed)
                except Exception:
                    pass

            if not pings:
                _inc_stat('xray_failed')
                return None

            avg = sum(pings) // len(pings)
            jit = sum(abs(p - avg) for p in pings) // len(pings) if len(pings) > 1 else 0

            # Проверяем лимиты
            if avg < MIN_XRAY_PING or avg > MAX_XRAY_PING:
                _inc_stat('xray_ping_out_of_range')
                return None
            if jit > MAX_XRAY_JITTER or (avg > 0 and jit > avg * MAX_XRAY_JITTER_RATIO):
                _inc_stat('xray_jitter_failed')
                return None

            # Измеряем скорость
            speed_mbps = _measure_speed(proxies)
            if XRAY_SPEED_MIN_MBPS > 0 and speed_mbps < XRAY_SPEED_MIN_MBPS:
                _inc_stat('xray_speed_too_low')
                return None

            if fetch_geo:
                try:
                    geo_resp = requests.get(
                        "http://ip-api.com/json/?fields=status,countryCode,isp,org,as,asname,hosting",
                        proxies=proxies,
                        timeout=XRAY_HTTP_TIMEOUT,
                        verify=False,
                    )
                    geo_data = geo_resp.json() if geo_resp.status_code == 200 else None
                except Exception:
                    geo_data = None
                return (avg, jit, speed_mbps, geo_data)

            return (avg, jit, speed_mbps)

        except Exception:
            _inc_stat('xray_failed')
            return None
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


def is_technically_broken(link: str, _lower: str | None = None) -> bool:
    l = _lower if _lower is not None else link.lower()
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
        for _ in range(FULL_PING_ATTEMPTS):
            if stop_event.is_set():
                return None
            time.sleep(FULL_PING_PAUSE)
            p = fast_ping(host, port, sni)
            if p is not None:
                if p < min_limit or p > max_limit:
                    _inc_stat('ping_out_of_range')
                    return None
                pings.append(p)

        if len(pings) < FULL_PING_MIN_SAMPLES:
            _inc_stat('packet_loss')
            return None

        avg = sum(pings) // len(pings)
        jit = sum(abs(p - avg) for p in pings) // len(pings)

        if jit > (avg * MAX_JITTER_RATIO) or jit > MAX_JITTER:
            _inc_stat('jitter_failed')
            return None

        return avg, jit
    except Exception:
        return None


def get_domain_mid(domain: str) -> str:
    """Возвращает предпоследнюю часть домена (основное имя без TLD)."""
    parts = domain.lower().split('.')
    return parts[-2] if len(parts) >= 2 else domain


def resolve_domain_host(domain: str) -> str | None:
    """Резолвит доменный хост в IPv4. Сначала проверяет persistent_domain_cache."""
    with _domain_host_lock:
        if domain in _domain_host_cache:
            return _domain_host_cache[domain]
    # Проверяем персистентный кэш
    if domain in persistent_domain_cache:
        ip = persistent_domain_cache[domain].get('ip')
        with _domain_host_lock:
            _domain_host_cache[domain] = ip
        return ip
    # DNS запрос
    try:
        result = socket.getaddrinfo(domain, None, socket.AF_INET)
        ip = result[0][4][0] if result else None
    except (socket.gaierror, OSError):
        ip = None
    with _domain_host_lock:
        _domain_host_cache[domain] = ip
    return ip


def get_config_details(link: str) -> tuple:
    try:
        clean_link = re.sub(r'[^\x20-\x7E]', '', link).strip()
        cid_match = re.search(r'://([^@]+)@', clean_link)
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', clean_link)
        s_m = re.search(r'[?&]sni=([^&#\s]*)', clean_link)
        if h_m:
            host_raw = h_m.group(1)
            sni = s_m.group(1).lower().split('?')[0].split('&')[0] if s_m else ""
            cid = cid_match.group(1) if cid_match else ""
            if is_valid_ipv4(host_raw):
                return host_raw, int(h_m.group(2)), sni, cid
            # Доменный хост — резолвим
            resolved = resolve_domain_host(host_raw)
            if resolved:
                return resolved, int(h_m.group(2)), sni, cid + f"|domain:{host_raw}"
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



def _load_cache_from_github(gh_repo, filename: str, label: str, ttl_days: int = 3) -> dict:
    """Универсальная загрузка кэша с GitHub."""
    if not gh_repo:
        return {}
    try:
        path = f"githubmirror/{filename}.json"
        file_content = gh_repo.get_contents(path)
        data = json.loads(file_content.decoded_content.decode('utf-8'))
        now = time.time()
        ttl_seconds = ttl_days * 86400
        filtered = {k: v for k, v in data.items() if now - v.get('ts', 0) < ttl_seconds}
        print(f"📦 Загружен {label}: {len(filtered)} записей", flush=True)
        return filtered
    except Exception:
        print(f"📦 {label} пуст или не найден", flush=True)
        return {}


def _save_cache_to_github(gh_repo, cache: dict, filename: str, label: str) -> None:
    """Универсальное сохранение кэша на GitHub."""
    if not gh_repo or not cache:
        return
    try:
        path = f"githubmirror/{filename}.json"
        content_str = json.dumps(cache, ensure_ascii=False, indent=2)
        try:
            sha = gh_repo.get_contents(path).sha
            gh_repo.update_file(path, f"{filename} update", content_str, sha)
        except Exception:
            gh_repo.create_file(path, f"{filename} create", content_str)
        print(f"💾 {label} сохранён: {len(cache)} записей", flush=True)
    except Exception as e:
        print(f"⚠️  Не удалось сохранить {label}: {e}", flush=True)


def load_persistent_ip_cache(gh_repo) -> None:
    global persistent_ip_cache, persistent_domain_cache, persistent_ws_cache
    persistent_ip_cache     = _load_cache_from_github(gh_repo, FILENAME_IP_CACHE,     "IP кэш",     IP_CACHE_TTL_DAYS)
    persistent_domain_cache = _load_cache_from_github(gh_repo, FILENAME_DOMAIN_CACHE, "Domain кэш", DOMAIN_CACHE_TTL_DAYS)
    persistent_ws_cache     = _load_cache_from_github(gh_repo, FILENAME_WS_CACHE,     "WS кэш",     WS_CACHE_TTL_DAYS)


def save_persistent_ip_cache(gh_repo) -> None:
    _save_cache_to_github(gh_repo, persistent_ip_cache,     FILENAME_IP_CACHE,     "IP кэш")
    _save_cache_to_github(gh_repo, persistent_domain_cache, FILENAME_DOMAIN_CACHE, "Domain кэш")
    _save_cache_to_github(gh_repo, persistent_ws_cache,     FILENAME_WS_CACHE,     "WS кэш")

def _api_wait_for_token() -> None:
    """Токен-бакет: выдаёт токен строго раз в API_RATE_LIMIT_INTERVAL секунд.
    Также учитывает Retry-After от 429 ответов."""
    global _api_last_token_time, _api_retry_after
    with _api_token_lock:
        now = time.perf_counter()
        # Ждём если есть активный Retry-After
        if _api_retry_after > now:
            time.sleep(_api_retry_after - now)
            now = time.perf_counter()
        # Токен-бакет: ждём до следующего доступного токена
        next_token = _api_last_token_time + API_RATE_LIMIT_INTERVAL
        if next_token > now:
            time.sleep(next_token - now)
        _api_last_token_time = time.perf_counter()


def check_isp_info(ip_str: str, is_ws_host: bool = False) -> tuple:
    global api_calls_count, _api_retry_after

    with lock:
        if ip_str in ip_cache:
            return ip_cache[ip_str]

    # Проверяем персистентный кэш
    if ip_str in persistent_ip_cache:
        v = persistent_ip_cache[ip_str]
        if 'isp' in v:
            full_info = f"{v.get('isp','')} {v.get('org','')} {v.get('as','')} {v.get('asname','')}".lower()
            if is_ws_host:
                is_bad = BAD_HOSTING_WS_ENABLED and any(w in full_info for w in BAD_HOSTING_KEYWORDS_WS)
            else:
                is_bad = BAD_HOSTING_ENABLED and any(w in full_info for w in BAD_HOSTING_KEYWORDS)
            is_banned_p = BANNED_ASNAME_ENABLED and any(p.lower() in full_info for p in BANNED_ASNAME_PATTERNS)
            is_banned = is_bad or is_banned_p
            is_api_h = v.get("hosting", False) and not is_bad
            is_kw_h = any(w in full_info for w in HOST_TAG_KEYWORDS)
            # Используем exit_cc если есть (страна выходного IP)
            cc = v.get('exit_cc') or v['cc']
            res = (cc, "BANNED" if is_banned else (is_api_h or is_kw_h))
        else:
            res = (v['cc'], v['hosting'])
        with lock:
            ip_cache[ip_str] = res
        return res

    with api_semaphore:
        for attempt in range(3):
            if stop_event.is_set():
                return None, False
            try:
                _api_wait_for_token()
                with stats_lock:
                    api_calls_count += 1

                resp = session.get(
                    f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,isp,org,as,asname,hosting",
                    timeout=5,
                )

                # Обработка 429 — читаем Retry-After
                if resp.status_code == 429:
                    retry_after = float(resp.headers.get("Retry-After", 10))
                    with _api_token_lock:
                        _api_retry_after = time.perf_counter() + retry_after
                    _inc_stat('isp_rate_limited')
                    continue

                resp.raise_for_status()
                r = resp.json()
                if r.get("status") == "success":
                    full_info = f"{r.get('isp','')} {r.get('org','')} {r.get('as','')} {r.get('asname','')}".lower()
                    if is_ws_host:
                        is_bad_hosting = BAD_HOSTING_WS_ENABLED and any(word in full_info for word in BAD_HOSTING_KEYWORDS_WS)
                    else:
                        is_bad_hosting = BAD_HOSTING_ENABLED and any(word in full_info for word in BAD_HOSTING_KEYWORDS)
                    is_banned_pattern = BANNED_ASNAME_ENABLED and any(pattern.lower() in full_info for pattern in BANNED_ASNAME_PATTERNS)
                    is_banned = is_bad_hosting or is_banned_pattern
                    if is_bad_hosting:
                        _inc_stat('banned_hosting')
                    if is_banned_pattern:
                        _inc_stat('banned_asname')
                    is_api_hosting = r.get("hosting", False) and not is_bad_hosting
                    is_kw_hosting = any(word in full_info for word in HOST_TAG_KEYWORDS)
                    is_hosting_flag = is_api_hosting or is_kw_hosting
                    res = (r.get("countryCode"), "BANNED" if is_banned else is_hosting_flag)
                    with lock:
                        ip_cache[ip_str] = res
                    raw_data = {
                        'cc': r.get("countryCode"),
                        'isp': r.get("isp", ""),
                        'org': r.get("org", ""),
                        'as': r.get("as", ""),
                        'asname': r.get("asname", ""),
                        'hosting': r.get("hosting", False),
                        'ts': time.time()
                    }
                    domain_ctx = getattr(check_isp_info, '_current_domain', None)
                    if domain_ctx:
                        persistent_domain_cache[domain_ctx] = dict(raw_data, ip=ip_str)
                        check_isp_info._current_domain = None
                    else:
                        persistent_ip_cache[ip_str] = raw_data
                    return res
            except (requests.RequestException, ValueError):
                if attempt < 2:
                    time.sleep(1.0)

    return None, False


check_isp_info._current_domain = None


def apply_clean_params(config_link: str) -> str:
    """Удаляет fp/udp443/note параметры и выставляет fp=random. Нормализует URL."""
    parts = config_link.split("#", 1)
    base = re.sub(r'[&?](?:fp|udp443|note)=[^&?#]+', '', parts[0])

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
        return count < MAX_HOST_NOWS_CONFIGS
    return True


def can_add_domain_host(is_domain_host: bool, domain_mid: str, is_vlm2: bool) -> bool:
    if not is_domain_host:
        return True
    count = domain_host_vlm2_count if is_vlm2 else domain_host_vlm_count
    if count >= MAX_DOMAIN_HOST_CONFIGS:
        return False
    if domain_mid and domain_mid_counts[domain_mid] >= MAX_DOMAIN_MID_CONFIGS:
        return False
    return True


def can_add_ws_host(is_ws_host: bool, is_vlm2: bool) -> bool:
    if is_ws_host:
        count = ws_host_vlm2_count if is_vlm2 else ws_host_vlm_count
        return count < MAX_WS_HOST_CONFIGS
    return True


def _evict_non_ru_sni(is_vlm2: bool) -> None:
    """Вытесняет один случайный не-RU SNI-RU конфиг в буфер."""
    global sni_vlm_count, sni_vlm2_count, host_vlm_count, host_vlm2_count
    results = vlm2_results if is_vlm2 else vlm_results
    buffer  = non_ru_sni_buffer_vlm2 if is_vlm2 else non_ru_sni_buffer_vlm
    candidates = [r for r in results if r['white_sni'] and r['country'] != 'RU']
    if not candidates:
        return
    victim = random.choice(candidates)
    results.remove(victim)
    buffer.append(victim)
    if is_vlm2:
        sni_vlm2_count -= 1
        if victim['is_hosting'] is True: host_vlm2_count -= 1
    else:
        sni_vlm_count -= 1
        if victim['is_hosting'] is True: host_vlm_count -= 1


def can_add_sni_ru(entry: dict, is_vlm2: bool) -> bool:
    """Проверяет не превышен ли лимит MAX_TOTAL_SNI_RU для данного списка.
    Динамически резервирует слоты для RU конфигов.
    """
    if not entry['white_sni']:
        return True
    # Во время повтора RU конфиги могут превышать лимит
    if sni_ru_retry_mode and entry['country'] == 'RU':
        return True
    current = sni_vlm2_count if is_vlm2 else sni_vlm_count
    ru_count = ru_vlm2_count if is_vlm2 else ru_vlm_count
    # Резервируем слоты для недобранных RU
    ru_needed = max(0, MIN_RU_CONFIGS - ru_count)
    effective_limit = MAX_TOTAL_SNI_RU - ru_needed
    if current >= effective_limit and entry['country'] != 'RU':
        # Вытесняем не-RU SNI-RU в буфер если есть место для RU
        _evict_non_ru_sni(is_vlm2)
        return False
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
    global ws_host_vlm_count, ws_host_vlm2_count, domain_host_vlm_count, domain_host_vlm2_count

    is_ru = (entry['country'] == 'RU')
    is_xhttp = entry['is_xhttp']
    is_hosting = entry['is_hosting']
    is_white = entry['white_sni']
    is_ws_host = entry.get('is_ws_host', False)
    is_domain_host = entry.get('is_domain_host', False)
    domain_mid = entry.get('domain_mid', '')

    added_vlm = False
    added_vlm2 = False

    if is_xhttp:
        if is_ru:
            if ru_vlm2_count < MAX_RU_CONFIGS and xhttp_count < MAX_XHTTP and can_add_hosting(is_hosting, True) and can_add_sni_ru(entry, True) and can_add_ws_host(is_ws_host, True) and can_add_domain_host(is_domain_host, domain_mid, True):
                vlm2_results.append(entry)
                ru_vlm2_count += 1
                xhttp_count += 1
                if is_hosting is True: host_vlm2_count += 1
                if is_ws_host: ws_host_vlm2_count += 1
                if is_domain_host: domain_host_vlm2_count += 1; domain_mid_counts[domain_mid] += 1
                if is_white: sni_vlm2_count += 1
                added_vlm2 = True
        else:
            if xhttp_count < MAX_XHTTP and len(vlm2_results) < MAX_CONFIGS and can_add_hosting(is_hosting, True) and can_add_sni_ru(entry, True) and can_add_ws_host(is_ws_host, True) and can_add_domain_host(is_domain_host, domain_mid, True):
                vlm2_results.append(entry)
                xhttp_count += 1
                if is_hosting is True: host_vlm2_count += 1
                if is_ws_host: ws_host_vlm2_count += 1
                if is_domain_host: domain_host_vlm2_count += 1; domain_mid_counts[domain_mid] += 1
                if is_white: sni_vlm2_count += 1
                added_vlm2 = True
    else:
        if is_ru:
            if ru_vlm_count < MAX_RU_CONFIGS and len(vlm_results) < MAX_CONFIGS and can_add_hosting(is_hosting, False) and can_add_sni_ru(entry, False) and can_add_ws_host(is_ws_host, False) and can_add_domain_host(is_domain_host, domain_mid, False):
                vlm_results.append(entry)
                ru_vlm_count += 1
                if is_hosting is True: host_vlm_count += 1
                if is_ws_host: ws_host_vlm_count += 1
                if is_domain_host: domain_host_vlm_count += 1; domain_mid_counts[domain_mid] += 1
                if is_white: sni_vlm_count += 1
                added_vlm = True
        elif len(vlm_results) < MAX_CONFIGS and can_add_hosting(is_hosting, False) and can_add_sni_ru(entry, False) and can_add_ws_host(is_ws_host, False) and can_add_domain_host(is_domain_host, domain_mid, False):
            vlm_results.append(entry)
            if is_hosting is True: host_vlm_count += 1
            if is_ws_host: ws_host_vlm_count += 1
            if is_domain_host: domain_host_vlm_count += 1; domain_mid_counts[domain_mid] += 1
            if is_white: sni_vlm_count += 1
            added_vlm = True

        reserved_for_xhttp = max(0, MIN_XHTTP - xhttp_count)
        vlm2_space = MAX_CONFIGS - reserved_for_xhttp
        if is_ru:
            if ru_vlm2_count < MAX_RU_CONFIGS and len(vlm2_results) < vlm2_space and can_add_hosting(is_hosting, True) and can_add_sni_ru(entry, True) and can_add_ws_host(is_ws_host, True) and can_add_domain_host(is_domain_host, domain_mid, True):
                vlm2_results.append(entry)
                ru_vlm2_count += 1
                if is_hosting is True: host_vlm2_count += 1
                if is_ws_host: ws_host_vlm2_count += 1
                if is_domain_host: domain_host_vlm2_count += 1; domain_mid_counts[domain_mid] += 1
                if is_white: sni_vlm2_count += 1
                added_vlm2 = True
        elif len(vlm2_results) < vlm2_space and can_add_hosting(is_hosting, True) and can_add_sni_ru(entry, True) and can_add_ws_host(is_ws_host, True) and can_add_domain_host(is_domain_host, domain_mid, True):
            vlm2_results.append(entry)
            if is_hosting is True: host_vlm2_count += 1
            if is_ws_host: ws_host_vlm2_count += 1
            if is_domain_host: domain_host_vlm2_count += 1; domain_mid_counts[domain_mid] += 1
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



_dns_cache: dict = {}
_dns_cache_lock = threading.Lock()


def resolve_ws_host(config: str) -> str | None:
    """Резолвит домен из параметра host= WS конфига, возвращает IP или None.
    Результат кэшируется чтобы не делать повторные DNS запросы для одного домена."""
    h_m = re.search(r'[?&]host=([^&#\s]+)', config, re.I)
    if not h_m:
        return None
    domain = h_m.group(1).lower()
    if not domain or is_valid_ipv4(domain):
        return domain if domain else None

    # Проверяем кэш
    with _dns_cache_lock:
        if domain in _dns_cache:
            return _dns_cache[domain]

    # Делаем DNS запрос
    result_ip = None
    try:
        result = socket.getaddrinfo(domain, None, socket.AF_INET)
        if result:
            result_ip = result[0][4][0]
    except (socket.gaierror, OSError):
        pass

    # Сохраняем в кэш (даже None — чтобы не повторять неудачные запросы)
    with _dns_cache_lock:
        _dns_cache[domain] = result_ip

    return result_ip


def _check_internet() -> bool:
    """Проверяет базовое интернет соединение через TCP до 8.8.8.8:53."""
    try:
        with socket.create_connection(("8.8.8.8", 53), timeout=3):
            return True
    except OSError:
        return False


def _wait_for_network() -> bool:
    """Ждёт восстановления сети. Возвращает True если восстановилась, False если нет."""
    global network_down, network_fail_counter
    for attempt in range(1, NETWORK_MAX_RETRIES + 1):
        time.sleep(NETWORK_CHECK_INTERVAL)
        if _check_internet():
            with network_lock:
                network_down = False
                network_fail_counter = 0
            print(f"🌐 Сеть восстановлена (попытка {attempt}/{NETWORK_MAX_RETRIES})", flush=True)
            return True
        print(f"🔴 Сеть недоступна (попытка {attempt}/{NETWORK_MAX_RETRIES})", flush=True)
    # Исчерпали попытки — останавливаем код
    print("❌ Сеть не восстановилась — останавливаем прогон", flush=True)
    stop_event.set()
    return False


def _register_ping_result(success: bool) -> None:
    """Регистрирует результат пинга и при необходимости запускает проверку сети."""
    global network_down, network_fail_counter
    with network_lock:
        if success:
            network_fail_counter = 0
            return
        network_fail_counter += 1
        if network_fail_counter >= NETWORK_FAIL_THRESHOLD and not network_down:
            network_down = True
            print(f"⚠️  Обнаружено падение сети ({NETWORK_FAIL_THRESHOLD} провалов подряд)", flush=True)


def validate(config: str, is_priority: bool, is_white: bool) -> None:
    if stop_event.is_set():
        _inc_stat('stopped')
        return
    # Ждём если сеть упала
    if network_down:
        if not _wait_for_network():
            return
    # Во время фазы SNI-RU останавливаемся по sni_ru_done_event
    if is_white and sni_ru_done_event.is_set():
        return

    # Определяем уникальность конфига для статистики + проверка повторов
    config_lower = config.lower()
    config_base = config_lower.split('#')[0]
    config_raw_key = (config_base, is_white)
    with lock:
        is_unique = config_base not in seen_configs
        if is_unique:
            seen_configs.add(config_base)
        if config_raw_key in checked_configs_raw:
            return
        checked_configs_raw.add(config_raw_key)

    if is_technically_broken(config, config_lower):
        if is_unique:
            _inc_stat('broken')
        return

    host, port, sni, cid = get_config_details(config)
    if not host or not sni:
        if is_unique:
            _inc_stat('no_details')
        return

    if f"{host}:{port}" in failed_ips:
        if is_unique:
            _inc_stat('failed_ip_cache')
        return

    # ── СЛОЙ 1: фильтр РКН (до пинга — быстро) ──────────────────────────────
    if is_blocked_in_ru(host):
        if is_unique:
            _inc_stat('blocked_rkn')
        return

    is_xhttp = "xhttp" in config_lower
    is_ws_host = "host=" in config_lower and "type=ws" in config_lower
    if is_ws_host and MAX_WS_HOST_CONFIGS == 0:
        return
    is_domain_host = "|domain:" in (cid or "")
    raw_domain = cid.split("|domain:")[-1] if is_domain_host and cid else ""
    domain_mid = get_domain_mid(raw_domain) if raw_domain else ""
    if is_domain_host and MAX_DOMAIN_HOST_CONFIGS == 0:
        return
    subnet = ".".join(host.split(".")[:3])
    subnet16 = ".".join(host.split(".")[:2])

    with lock:
        if host in seen_ips:
            if is_unique:
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

        # Предварительные лимитные проверки до пинга
        # ws_host лимит
        if is_ws_host and ws_host_vlm_count >= MAX_WS_HOST_CONFIGS and ws_host_vlm2_count >= MAX_WS_HOST_CONFIGS:
            _inc_stat('ws_host_limit')
            return
        # domain_host лимиты
        if is_domain_host:
            if domain_host_vlm_count >= MAX_DOMAIN_HOST_CONFIGS and domain_host_vlm2_count >= MAX_DOMAIN_HOST_CONFIGS:
                _inc_stat('domain_host_limit')
                return
            if domain_mid and domain_mid_counts[domain_mid] >= MAX_DOMAIN_MID_CONFIGS:
                _inc_stat('domain_mid_limit')
                return
            if raw_domain and failed_domain_counts[f"{raw_domain}:{port}"] >= MAX_FAILED_PER_DOMAIN:
                _inc_stat('failed_domain_cache')
                return
            # Резервируем слот domain_mid
            if domain_mid:
                domain_mid_counts[domain_mid] += 1

        # SNI-RU лимит (в обычном режиме страна не нужна)
        if not sni_ru_retry_mode and is_white:
            if sni_vlm_count >= MAX_TOTAL_SNI_RU and sni_vlm2_count >= MAX_TOTAL_SNI_RU:
                _inc_stat('sni_ru_limit_early')
                return

    # Первый пинг
    p1 = fast_ping(host, port, sni)
    initial_max_p = MAX_WORLD_PING_XHTTP if is_xhttp else MAX_WORLD_PING
    if not p1 or p1 > initial_max_p:
        with lock:
            failed_subnets[subnet] += 1
            failed_ips.add(f"{host}:{port}")
            if is_domain_host and raw_domain:
                failed_domain_counts[f"{raw_domain}:{port}"] += 1
            if is_domain_host and domain_mid:
                domain_mid_counts[domain_mid] -= 1
        _inc_stat('first_ping_failed')
        return

    # Проверка ISP
    ws_cache_key = None
    ws_geo_needed = False
    config_type = "others"  # будет переопределено после получения ip_cc
    if is_ws_host:
        h_m2 = re.search(r'[?&]host=([^&#\s]+)', config, re.I)
        ws_host_domain = h_m2.group(1).lower() if h_m2 else ""
        ws_cache_key = f"{ws_host_domain}:{sni}"
        if ws_cache_key in persistent_ws_cache:
            v = persistent_ws_cache[ws_cache_key]
            full_info = f"{v.get('isp','')} {v.get('org','')} {v.get('as','')} {v.get('asname','')}".lower()
            is_bad = BAD_HOSTING_WS_ENABLED and any(w in full_info for w in BAD_HOSTING_KEYWORDS_WS)
            is_banned_p = BANNED_ASNAME_ENABLED and any(p.lower() in full_info for p in BANNED_ASNAME_PATTERNS)
            is_banned = is_bad or is_banned_p
            is_api_h = v.get("hosting", False) and not is_bad
            is_kw_h = any(w in full_info for w in HOST_TAG_KEYWORDS)
            ip_cc = v.get("cc", "")
            ip_h_stat = "BANNED" if is_banned else (is_api_h or is_kw_h)
        else:
            ws_geo_needed = True
            ip_cc = "UNKNOWN"
            ip_h_stat = False
    elif is_domain_host and raw_domain:
        check_isp_info._current_domain = raw_domain
        ip_cc, ip_h_stat = check_isp_info(host, is_ws_host=False)
    else:
        ip_cc, ip_h_stat = check_isp_info(host, is_ws_host=False)

    if not ws_geo_needed:
        if stop_event.is_set():
            return
        if not ip_cc:
            _inc_stat('isp_no_response')
            return
        if ip_h_stat == "BANNED":
            _inc_stat('isp_banned')
            return
        if ip_cc == "RU" and not is_white:
            _inc_stat('ru_without_white_sni')
            return

    # Проверка лимита подсети /16 (для ws_geo_needed пропускаем — ip_cc неизвестен)
    subnet16_reserved = False
    sni_reserved = False
    if not ws_geo_needed:
        config_type = get_config_type(ip_cc, is_white)
        subnet16_limit = get_subnet16_limit(config_type)
        with lock:
            if subnet16_counts[subnet16][config_type] >= subnet16_limit:
                _inc_stat('subnet16_limit')
                return
            subnet16_counts[subnet16][config_type] += 1
            subnet16_reserved = True
        with lock:
            sni_limit = get_sni_limit(is_white, ip_cc)
            if sni_usage_counts[sni] >= sni_limit:
                _inc_stat('sni_limit')
                return
            sni_usage_counts[sni] += 1
            sni_reserved = True

    is_ru = (ip_cc == "RU")
    if is_xhttp:
        min_p = MIN_RU_PING if is_ru else MIN_WORLD_PING
        max_p = MAX_RU_PING_XHTTP if is_ru else MAX_WORLD_PING_XHTTP
    else:
        min_p = MIN_RU_PING if is_ru else MIN_WORLD_PING
        max_p = MAX_RU_PING if is_ru else MAX_WORLD_PING

    # ── Полный анализ TCP пинга: потеря пакетов + jitter ─────────────────────
    full = full_ping_analysis(host, port, sni, p1, min_p, max_p)
    if not full:
        if sni_reserved:
            with lock:
                sni_usage_counts[sni] -= 1
        if subnet16_reserved:
            with lock:
                subnet16_counts[subnet16][config_type] -= 1
        if is_domain_host and domain_mid:
            with lock:
                domain_mid_counts[domain_mid] -= 1
        return

    # ── XRAY-ТЕСТ: реальная проверка туннеля + измерение пинга via proxy get ──
    # fetch_geo только если hosting=True (для уточнения выходной страны) или WS конфиг
    need_exit_geo = ws_geo_needed or (ip_h_stat is True)
    xray_result = xray_test(config, is_ru=is_ru, fetch_geo=need_exit_geo)
    if xray_result is None:
        if sni_reserved:
            with lock:
                sni_usage_counts[sni] -= 1
        if subnet16_reserved:
            with lock:
                subnet16_counts[subnet16][config_type] -= 1
        if (is_domain_host or is_ws_host) and domain_mid:
            with lock:
                domain_mid_counts[domain_mid] -= 1
        return

    xray_ping = xray_result[0]
    xray_jitter = xray_result[1]
    xray_speed = xray_result[2] if len(xray_result) >= 3 and isinstance(xray_result[2], float) else 0.0
    geo_data = xray_result[3] if len(xray_result) == 4 else (xray_result[2] if len(xray_result) == 3 and not isinstance(xray_result[2], float) else None)

    if need_exit_geo and geo_data is not None:
        if geo_data and geo_data.get("status") == "success":
            exit_cc = geo_data.get("countryCode", "")
            if is_ws_host:
                # WS конфиг — применяем все правила по выходному IP
                full_info = f"{geo_data.get('isp','')} {geo_data.get('org','')} {geo_data.get('as','')} {geo_data.get('asname','')}".lower()
                is_bad = BAD_HOSTING_WS_ENABLED and any(w in full_info for w in BAD_HOSTING_KEYWORDS_WS)
                is_banned_p = BANNED_ASNAME_ENABLED and any(p.lower() in full_info for p in BANNED_ASNAME_PATTERNS)
                is_banned = is_bad or is_banned_p
                if is_bad: _inc_stat('banned_hosting')
                if is_banned_p: _inc_stat('banned_asname')
                is_api_h = geo_data.get("hosting", False) and not is_bad
                is_kw_h = any(w in full_info for w in HOST_TAG_KEYWORDS)
                ip_h_stat = "BANNED" if is_banned else (is_api_h or is_kw_h)
                if ws_cache_key:
                    persistent_ws_cache[ws_cache_key] = {
                        'cc': exit_cc, 'isp': geo_data.get('isp',''),
                        'org': geo_data.get('org',''), 'as': geo_data.get('as',''),
                        'asname': geo_data.get('asname',''), 'hosting': geo_data.get('hosting', False),
                        'ts': time.time()
                    }
                if exit_cc:
                    ip_cc = exit_cc
                is_ru = (ip_cc == "RU")
                if ws_geo_needed:
                    if not ip_cc or ip_h_stat == "BANNED" or (ip_cc == "RU" and not is_white):
                        if not ip_cc: _inc_stat('isp_no_response')
                        elif ip_h_stat == "BANNED": _inc_stat('isp_banned')
                        else: _inc_stat('ru_without_white_sni')
                        return
                    config_type = get_config_type(ip_cc, is_white)
                    subnet16_limit = get_subnet16_limit(config_type)
                    with lock:
                        if subnet16_counts[subnet16][config_type] >= subnet16_limit:
                            _inc_stat('subnet16_limit')
                            return
                        subnet16_counts[subnet16][config_type] += 1
                        subnet16_reserved = True
                    with lock:
                        sni_limit = get_sni_limit(is_white, ip_cc)
                        if sni_usage_counts[sni] >= sni_limit:
                            _inc_stat('sni_limit')
                            return
                        sni_usage_counts[sni] += 1
                        sni_reserved = True
            else:
                # Обычный hosting конфиг — берём только страну с выходного IP
                # Все остальные правила уже применены по входному IP
                if exit_cc:
                    ip_cc = exit_cc
                    # Сохраняем exit_cc в ip_cache для следующего прогона
                    if host in persistent_ip_cache:
                        persistent_ip_cache[host]['exit_cc'] = exit_cc
                is_ru = (ip_cc == "RU")
        else:
            if ws_geo_needed:
                _inc_stat('isp_no_response')
                return
    # Если xray недоступен — используем TCP пинг как fallback
    display_ping = xray_ping if xray_ping > 0 else p1

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
            "ping": display_ping,
            "country": ip_cc,
            "is_priority": is_priority,
            "white_sni": is_white,
            "is_hosting": ip_h_stat,
            "is_xhttp": is_xhttp,
            "is_ws_host": is_ws_host,
            "is_domain_host": is_domain_host,
            "domain_mid": domain_mid,
            "speed_mbps": xray_speed,
        }

        if try_add_to_lists(entry):
            seen_ips.add(host)
            subnet_counts[subnet] += 1
            id_counts[cid] += 1

            host_tag = " (X)" if is_xhttp else ""
            sni_tag = " SNI-RU" if is_white else ""
            speed_tag = f" | {xray_speed:.1f}Мбит/с" if xray_speed > 0 else ""
            print(f"[FOUND{host_tag}] {ip_cc} | {display_ping}ms{speed_tag} | {host}{sni_tag}", flush=True)
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
            if is_domain_host and domain_mid:
                domain_mid_counts[domain_mid] -= 1
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

        count = 0
        while count < INTERLEAVE_STEP and len(final) < MAX_CONFIGS and (non_ru_dq or xhttp_dq):
            src = non_ru_dq if non_ru_dq else xhttp_dq
            config = src.popleft()
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


def _restore_non_ru_sni_buffer() -> None:
    """Возвращает буферизованные не-RU SNI-RU конфиги обратно если RU слоты не заняты."""
    global sni_vlm_count, sni_vlm2_count, host_vlm_count, host_vlm2_count
    with lock:
        for results, buffer, is_vlm2 in [
            (vlm_results,  non_ru_sni_buffer_vlm,  False),
            (vlm2_results, non_ru_sni_buffer_vlm2, True),
        ]:
            ru_count  = ru_vlm2_count if is_vlm2 else ru_vlm_count
            ru_needed = max(0, MIN_RU_CONFIGS - ru_count)
            # Возвращаем столько конфигов из буфера сколько слотов свободно
            slots_free = MAX_TOTAL_SNI_RU - (sni_vlm2_count if is_vlm2 else sni_vlm_count)
            can_restore = max(0, slots_free - ru_needed)
            to_restore = buffer[:can_restore]
            for r in to_restore:
                results.append(r)
                buffer.remove(r)
                if is_vlm2:
                    sni_vlm2_count += 1
                    if r['is_hosting'] is True: host_vlm2_count += 1
                else:
                    sni_vlm_count += 1
                    if r['is_hosting'] is True: host_vlm_count += 1


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
        _sni_extra = stats['sni_ru_from_extra']
        _sni_std   = stats['sni_ru_from_std']

    print("\n--- 📊 СТАТИСТИКА ---", flush=True)
    print(f"Добавлено: {s['added']}", flush=True)

    print("\n[Локальные проверки]", flush=True)
    print(f"Технически битые: {s['broken']}", flush=True)
    print(f"Без деталей: {s['no_details']}", flush=True)
    print(f"Заблокировано РКН: {s['blocked_rkn']}", flush=True)
    print(f"Дубликаты IP: {s['duplicate_ip']}", flush=True)
    print(f"Кэш неудачных IP: {s['failed_ip_cache']}", flush=True)
    print(f"Исключён по SNI домену: {s['excluded_sni']}", flush=True)
    print(f"Лимиты подсети: {s['subnet_limit']}", flush=True)

    print("\n[Сетевые проверки]", flush=True)
    print(f"Первый пинг провален: {s['first_ping_failed']}", flush=True)
    print(f"Запросов к ip-api: {_api} (кэш попаданий: {s['duplicate_ip'] + s['race_duplicate']})", flush=True)
    print(f"ISP не ответил: {s['isp_no_response']}", flush=True)
    print(f"ISP rate limit (429): {s['isp_rate_limited']}", flush=True)
    print(f"ISP забанен: {s['isp_banned']}", flush=True)
    print(f"Плохой хостинг (BAD_HOSTING): {s['banned_hosting']}", flush=True)
    print(f"Забанен по ASN паттерну: {s['banned_asname']}", flush=True)
    print(f"Лимиты SNI: {s['sni_limit']}", flush=True)
    print(f"Подсеть забанена: {s['subnet_banned']}", flush=True)
    print(f"Не добавлено (нет места): {s['not_added']}", flush=True)
    print(f"Потеря пакетов TCP: {s['packet_loss']}", flush=True)
    print(f"Jitter TCP провален: {s['jitter_failed']}", flush=True)
    print(f"Пинг TCP вне диапазона: {s['ping_out_of_range']}", flush=True)
    print(f"Не прошло Xray-тест: {s['xray_failed']}", flush=True)
    print(f"Xray пинг вне диапазона: {s['xray_ping_out_of_range']}", flush=True)
    print(f"Xray jitter провален: {s['xray_jitter_failed']}", flush=True)
    print(f"Xray скорость низкая: {s['xray_speed_too_low']}", flush=True)

    print("\n[Итог]", flush=True)
    with lock:
        _dh_vlm  = domain_host_vlm_count
        _dh_vlm2 = domain_host_vlm2_count
    print(f"VLM: {vlm_len} (RU: {_ru_vlm}, HOST: {vlm_host}, DOMAIN: {_dh_vlm})", flush=True)
    print(f"VLM2: {vlm2_len} (RU: {_ru_vlm2}, XHTTP: {_xhttp}, HOST: {vlm2_host}, DOMAIN: {_dh_vlm2})", flush=True)
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

    load_persistent_ip_cache(gh_repo)
    load_ru_blocklist()

    raw_extra, raw_std = fetch_group_data(extra_urls), fetch_group_data(std_urls)
    print(f"Уникальных конфигов: Extra={len(raw_extra)}, Std={len(raw_std)}", flush=True)

    def _has_white_sni(config: str) -> bool:
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
    if not RU_RETRY_ENABLED:
        sni_ru_done_event.set()
    for attempt in range(1, RU_RETRY_MAX + 1) if RU_RETRY_ENABLED else []:
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

        # Очищаем белые записи из checked_configs_raw чтобы повтор мог проверить те же конфиги
        with lock:
            working_raw = set()
            for r in vlm_results + vlm2_results:
                base = r['link'].split('#')[0]
                working_raw.add((base, True))
            checked_configs_raw -= {k for k in checked_configs_raw if k[1] is True and k not in working_raw}

        raw_extra_retry = fetch_group_data(extra_urls)
        raw_std_retry   = fetch_group_data(std_urls)
        print(
            f"🔁 Повтор SNI-RU: Extra={len(raw_extra_retry)}, Std={len(raw_std_retry)}",
            flush=True,
        )

        global sni_ru_retry_mode
        # Сбрасываем sni_ru_done_event
        sni_ru_done_event.clear()

        with lock:
            orig_vlm_len  = len(vlm_results)
            orig_vlm2_len = len(vlm2_results)

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
    # Сначала восстанавливаем буфер если RU не добрали
    _restore_non_ru_sni_buffer()

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

    save_persistent_ip_cache(gh_repo)
    print(f"--- 🏁 ГОТОВО за {time.perf_counter() - start_total:.1f}с ---")


if __name__ == "__main__":
    main()

