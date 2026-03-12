"""
find_ru_proxy.py
Ищет рабочий RU+SNI-RU конфиг, запускает Xray как постоянный SOCKS5 прокси,
записывает адрес прокси в GITHUB_ENV для использования в main.py.
"""

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
from collections import defaultdict

import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- НАСТРОЙКИ ---
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
SECONDARY_WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt"

XRAY_BINARY = os.environ.get("XRAY_BINARY", "/tmp/xray/xray")
XRAY_PROXY_PORT = 10800          # порт постоянного прокси
XRAY_TEST_URL = "https://cp.cloudflare.com"
XRAY_STARTUP_WAIT = 2.5
XRAY_TIMEOUT = 6
XRAY_PROCESS_TIMEOUT = 5
XRAY_PORT_BASE = 11000           # порты для временных тест-процессов

FAST_PING_TIMEOUT = 1.2
MIN_RU_PING = 10.0
MAX_RU_PING = 500.0
MAX_JITTER = 80
MAX_JITTER_RATIO = 0.4
FULL_PING_PAUSE = 0.15
FULL_PING_ATTEMPTS = 3
FULL_PING_MIN_SAMPLES = 2

MAX_WORKERS = 20
MAX_CANDIDATES = 5               # сколько рабочих RU конфигов попробовать прежде чем выбрать лучший

session = requests.Session()
session.headers.update({'Connection': 'keep-alive'})

_port_counter = XRAY_PORT_BASE
_port_lock = threading.Lock()
_found_lock = threading.Lock()
found_configs = []               # список рабочих (link, ping)
stop_event = threading.Event()


def get_port() -> int:
    global _port_counter
    with _port_lock:
        p = _port_counter
        _port_counter += 1
    return p


def is_valid_ipv4(ip: str) -> bool:
    try:
        import ipaddress
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


def get_config_details(link: str):
    try:
        clean_link = re.sub(r'[^\x20-\x7E]', '', link).strip()
        h_m = re.search(r'@([^:/?#\s]+):(\d+)', clean_link)
        s_m = re.search(r'[?&]sni=([^&#\s]*)', clean_link)
        if h_m and is_valid_ipv4(h_m.group(1)):
            sni = s_m.group(1).lower().split('?')[0].split('&')[0] if s_m else ""
            return h_m.group(1), int(h_m.group(2)), sni
    except (AttributeError, ValueError):
        pass
    return None, None, None


def fast_ping(host: str, port: int, sni: str) -> int | None:
    try:
        start = time.perf_counter()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=FAST_PING_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=sni if sni else None):
                return int((time.perf_counter() - start) * 1000)
    except Exception:
        return None


def full_ping(host: str, port: int, sni: str, p1: int) -> int | None:
    pings = [p1]
    for _ in range(FULL_PING_ATTEMPTS):
        time.sleep(FULL_PING_PAUSE)
        p = fast_ping(host, port, sni)
        if p is not None:
            if p < MIN_RU_PING or p > MAX_RU_PING:
                return None
            pings.append(p)
    if len(pings) < FULL_PING_MIN_SAMPLES:
        return None
    avg = sum(pings) // len(pings)
    jit = sum(abs(p - avg) for p in pings) // len(pings)
    if jit > (avg * MAX_JITTER_RATIO) or jit > MAX_JITTER:
        return None
    return avg


def build_xray_config(config_link: str, socks_port: int) -> dict | None:
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
        stream_settings = {
            "network": "tcp",
            "security": security,
            tls_key: tls_settings,
        }

    if security == "none":
        stream_settings.pop("tlsSettings", None)
        stream_settings.pop("realitySettings", None)

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": "socks",
            "port": socks_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [
            {
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
            },
            {"tag": "direct", "protocol": "freedom"},
        ],
    }


def xray_test_config(config_link: str) -> bool:
    """Тестирует конфиг через временный Xray процесс. Возвращает True если рабочий."""
    socks_port = get_port()
    xray_cfg = build_xray_config(config_link, socks_port)
    if not xray_cfg:
        return False

    proc = None
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, prefix='xru_') as tmp:
            json.dump(xray_cfg, tmp)
            tmp_path = tmp.name

        proc = subprocess.Popen(
            [XRAY_BINARY, "run", "-config", tmp_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(XRAY_STARTUP_WAIT)

        if proc.poll() is not None:
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
        return r.status_code in (200, 204)

    except Exception:
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


def check_candidate(config: str, sni_domains: set) -> None:
    """Проверяет один конфиг — только RU+SNI-RU."""
    if stop_event.is_set():
        return
    if is_technically_broken(config):
        return

    host, port, sni = get_config_details(config)
    if not host or not sni:
        return
    if sni not in sni_domains:
        return  # не SNI-RU

    # Быстрый пинг
    p1 = fast_ping(host, port, sni)
    if not p1 or p1 < MIN_RU_PING or p1 > MAX_RU_PING:
        return

    # Полный анализ пинга
    avg = full_ping(host, port, sni, p1)
    if not avg:
        return

    # Xray тест
    if not xray_test_config(config):
        return

    with _found_lock:
        if stop_event.is_set():
            return
        found_configs.append((config, avg))
        print(f"✅ [RU PROXY FOUND] {host} | {avg}ms", flush=True)
        if len(found_configs) >= MAX_CANDIDATES:
            stop_event.set()


def fetch_raw_configs(url: str) -> list[str]:
    try:
        resp = session.get(url, timeout=7, verify=False).text
        if "://" not in resp[:50]:
            try:
                resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
            except Exception:
                pass
        return [l.strip() for l in re.findall(r'(?:vless|ssr|tuic|hysteria|hysteria2)://[^\s]+', resp)]
    except Exception:
        return []


def fetch_group_data(urls: list[str]) -> list[str]:
    raw = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(fetch_raw_configs, u) for u in set(urls)]
        for f in concurrent.futures.as_completed(futures):
            raw.extend(f.result())
    unique = list(set(raw))
    random.shuffle(unique)
    return unique


def start_permanent_proxy(config_link: str) -> subprocess.Popen | None:
    """Запускает Xray как постоянный SOCKS5 прокси на порту XRAY_PROXY_PORT."""
    xray_cfg = build_xray_config(config_link, XRAY_PROXY_PORT)
    if not xray_cfg:
        return None

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, prefix='xru_proxy_') as tmp:
            json.dump(xray_cfg, tmp)
            tmp_path = tmp.name

        proc = subprocess.Popen(
            [XRAY_BINARY, "run", "-config", tmp_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(XRAY_STARTUP_WAIT)

        if proc.poll() is not None:
            print("❌ Постоянный прокси упал при старте", flush=True)
            return None

        # Проверяем что прокси реально работает
        proxies = {
            "http":  f"socks5://127.0.0.1:{XRAY_PROXY_PORT}",
            "https": f"socks5://127.0.0.1:{XRAY_PROXY_PORT}",
        }
        r = requests.get(XRAY_TEST_URL, proxies=proxies, timeout=8, verify=False)
        if r.status_code not in (200, 204):
            proc.terminate()
            return None

        print(f"🚀 Постоянный RU прокси запущен на порту {XRAY_PROXY_PORT}", flush=True)
        return proc

    except Exception as e:
        print(f"❌ Ошибка запуска постоянного прокси: {e}", flush=True)
        return None


def write_proxy_to_github_env(proxy_url: str) -> None:
    """Записывает переменную RU_PROXY в GITHUB_ENV."""
    github_env = os.environ.get("GITHUB_ENV")
    if github_env:
        with open(github_env, "a") as f:
            f.write(f"RU_PROXY={proxy_url}\n")
        print(f"📝 RU_PROXY записан в GITHUB_ENV: {proxy_url}", flush=True)
    else:
        print(f"⚠️  GITHUB_ENV не найден, RU_PROXY: {proxy_url}", flush=True)


def main():
    print("--- 🔍 ПОИСК RU ПРОКСИ ---", flush=True)

    # Проверяем Xray
    try:
        result = subprocess.run([XRAY_BINARY, "version"], capture_output=True, timeout=XRAY_PROCESS_TIMEOUT)
        if result.returncode != 0:
            print("❌ Xray недоступен, пропускаем поиск прокси", flush=True)
            return
    except Exception:
        print("❌ Xray недоступен, пропускаем поиск прокси", flush=True)
        return

    # Загружаем SNI домены и списки конфигов
    sni_domains = set()
    extra_urls, std_urls = [], []
    try:
        src_text = session.get(REMOTE_SOURCE_URL, timeout=10).text

        def get_list(var: str) -> list[str]:
            m = re.search(rf'{var}\s*=\s*\[(.*?)\]', src_text, re.S | re.I)
            return re.findall(r'["\']([^"\']+)["\']', m.group(1)) if m else []

        extra_urls = get_list("EXTRA_URLS_FOR_26")
        std_urls = get_list("URLS")
        sni_domains.update(s.lower() for s in get_list("SNI_DOMAINS"))

        sec_text = session.get(SECONDARY_WHITELIST_URL, timeout=10).text
        sni_domains.update(line.strip().lower() for line in sec_text.splitlines() if line.strip())
    except Exception as e:
        print(f"⚠️  Не удалось загрузить источники: {e}", flush=True)
        return

    print(f"SNI доменов: {len(sni_domains)}, Extra URLs: {len(extra_urls)}, Std URLs: {len(std_urls)}", flush=True)

    # Берём только extra_urls — там приоритетные RU конфиги
    raw = fetch_group_data(extra_urls + std_urls)
    print(f"Конфигов для проверки: {len(raw)}", flush=True)

    # Ищем рабочие RU+SNI-RU конфиги параллельно
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for config in raw:
            if stop_event.is_set():
                break
            executor.submit(check_candidate, config, sni_domains)

    if not found_configs:
        print("⚠️  Рабочий RU прокси не найден, main.py будет работать напрямую", flush=True)
        return

    # Выбираем лучший по пингу
    best_config, best_ping = min(found_configs, key=lambda x: x[1])
    print(f"🏆 Лучший RU конфиг: пинг {best_ping}ms", flush=True)

    # Запускаем постоянный прокси
    proc = start_permanent_proxy(best_config)
    if not proc:
        print("⚠️  Не удалось запустить постоянный прокси, main.py будет работать напрямую", flush=True)
        return

    # Записываем в GITHUB_ENV
    proxy_url = f"socks5://127.0.0.1:{XRAY_PROXY_PORT}"
    write_proxy_to_github_env(proxy_url)
    print("--- ✅ RU ПРОКСИ ГОТОВ ---", flush=True)


if __name__ == "__main__":
    main()
      
