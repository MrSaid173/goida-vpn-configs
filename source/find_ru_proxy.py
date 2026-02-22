# find_ru_proxy.py
# Ищет один рабочий RU конфиг (SNI-RU, не HOST) для использования как прокси во второй джобе.
# Результат сохраняет в proxy_config.json (Xray-формат) и proxy_link.txt (исходная ссылка).

import os, re, requests, urllib3, base64, json, time, socket, ssl, random
import subprocess, tempfile, threading, concurrent.futures
from collections import defaultdict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Настройки (берём те же источники что и основной скрипт) ---
REMOTE_SOURCE_URL  = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
SECONDARY_WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt"

XRAY_BIN           = os.environ.get("XRAY_BIN", "xray")
PROXY_SOCKS_PORT   = 10808          # порт на котором поднимется прокси для второй джобы
XRAY_STARTUP_DELAY = 1.5
XRAY_HTTP_TIMEOUT  = 6
CHECK_URL          = "http://cp.cloudflare.com/"

MAX_PING           = 600            # мс — максимальный TCP-пинг для RU конфига
MIN_PING           = 50             # мс — минимальный (слишком быстрый = подозрительно)
MAX_WORKERS        = 30
MAX_PROXY_CONFIGS  = 5              # сколько рабочих конфигов собрать про запас

BAD_HOSTING_KEYWORDS = [
    "cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google",
    "microsoft", "ovh", "linode", "servers", "work", "oracle", "leaseweb",
    "m247", "akamai", "host" #"baykov", "dataforest", "yandex", "selectel",
    #"timeweb", "beget"
]
EXCLUDED_SNI = ["userapi", "splitter.wb.ru"]

session = requests.Session()
result_lock = threading.Lock()
found_configs = []   # список рабочих конфигов: {"link": ..., "xray_json": ..., "ping": ...}
stop_collecting = threading.Event()


# ── helpers ──────────────────────────────────────────────────────────────────

def is_valid_ipv4(ip):
    import ipaddress
    try:
        ipaddress.IPv4Address(ip)
        return True
    except:
        return False


def get_config_details(link):
    try:
        clean = re.sub(r'[^\x20-\x7E]', '', link).strip()
        cid_m = re.search(r'://([^@]+)@', clean)
        h_m   = re.search(r'@([^:/?#\s]+):(\d+)', clean)
        s_m   = re.search(r'[?&]sni=([^&#\s]*)', clean)
        if h_m and is_valid_ipv4(h_m.group(1)):
            sni = s_m.group(1).lower().split('?')[0].split('&')[0] if s_m else ""
            return h_m.group(1), int(h_m.group(2)), sni, cid_m.group(1) if cid_m else ""
    except:
        pass
    return None, None, None, None


def fast_ping(host, port, sni):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=2.0) as s:
            with ctx.wrap_socket(s, server_hostname=sni or None):
                return int((time.perf_counter() - start) * 1000)
    except:
        return None


def check_isp_ru_nonhosting(ip):
    """Возвращает True если IP — российский и не плохой хостинг."""
    try:
        r = session.get(
            f"http://ip-api.com/json/{ip}?fields=status,countryCode,isp,org,as,asname,hosting",
            timeout=5
        ).json()
        if r.get("status") != "success":
            return False
        if r.get("countryCode") != "RU":
            return False
        full = f"{r.get('isp')} {r.get('org')} {r.get('as')} {r.get('asname')}".lower()
        if any(w in full for w in BAD_HOSTING_KEYWORDS):
            return False
        return True
    except:
        return False


def is_broken(link):
    l = link.lower()
    if "type=" not in l:           return True
    if "type=splithttp" in l:      return True
    if "type=grpc" in l:           return True
    if re.search(r':(443|80)/\?', l): return True
    if "/??" in l:                 return True
    if "host=" in l:               return True
    if "security=reality" not in l and "security=tls" not in l:
        return True
    s_m = re.search(r'[?&]sni=([^&#\s]*)', l)
    if not s_m:                    return True
    if is_valid_ipv4(s_m.group(1)): return True
    if "pbk=" in l and ("security=tls" in l or ":80?" in l): return True
    if "flow=xtls-rprx-vision" in l and "type=tcp" not in l: return True
    h_m = re.search(r'@([^:/?#\s]+):(\d+)', l)
    if h_m and not (1 <= int(h_m.group(2)) <= 65535): return True
    return False


def build_xray_config(link, socks_port):
    """Строит полный Xray JSON (inbound SOCKS + outbound VLESS)."""
    host, port, sni, cid = get_config_details(link)
    if not host or not cid:
        return None

    l  = link
    ll = link.lower()

    network = "tcp"
    if "type=ws" in ll:   network = "ws"
    elif "xhttp" in ll:   network = "xhttp"

    path_m = re.search(r'[?&]path=([^&#\s]*)', l)
    path   = requests.utils.unquote(path_m.group(1)) if path_m else "/"

    security = "none"
    if "security=tls"     in ll: security = "tls"
    elif "security=reality" in ll: security = "reality"

    flow  = "xtls-rprx-vision" if "flow=xtls-rprx-vision" in ll else ""
    fp_m  = re.search(r'[?&]fp=([^&#\s]*)', ll)
    fp    = fp_m.group(1) if fp_m else "chrome"
    if fp == "random": fp = "chrome"

    pbk_m = re.search(r'[?&]pbk=([^&#\s]*)', l)
    sid_m = re.search(r'[?&]sid=([^&#\s]*)', l)

    stream = {"network": network, "security": security}
    if network == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": sni}}
    elif network == "xhttp":
        stream["xhttpSettings"] = {"path": path, "host": sni}

    if security == "tls":
        stream["tlsSettings"] = {"serverName": sni, "allowInsecure": True, "fingerprint": fp}
    elif security == "reality":
        if not pbk_m: return None
        stream["realitySettings"] = {
            "serverName": sni, "fingerprint": fp,
            "publicKey": pbk_m.group(1),
            "shortId": sid_m.group(1) if sid_m else ""
        }

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "0.0.0.0",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False}
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": host, "port": port,
                "users": [{"id": cid, "encryption": "none", "flow": flow}]
            }]},
            "streamSettings": stream
        }]
    }


def test_config(link, sni_domains):
    """Полная проверка одного конфига: broken → ping → ISP → Xray."""
    if stop_collecting.is_set():
        return

    if is_broken(link):
        return

    host, port, sni, cid = get_config_details(link)
    if not host or not sni:
        return

    # SNI должен быть в белом списке (SNI-RU)
    if sni not in sni_domains:
        return
    if any(exc in sni for exc in EXCLUDED_SNI):
        return

    p = fast_ping(host, port, sni)
    if not p or p < MIN_PING or p > MAX_PING:
        return

    print(f"  PING OK {host} | {p}ms | {sni}", flush=True)

    if not check_isp_ru_nonhosting(host):
        print(f"  ISP FAIL {host}", flush=True)
        return

    print(f"  ISP OK {host} — проверяем через Xray...", flush=True)

    # Порт для этого конкретного Xray-процесса — уникальный чтобы не конфликтовать
    with result_lock:
        socks_port = PROXY_SOCKS_PORT + len(found_configs)

    xray_cfg = build_xray_config(link, socks_port)
    if not xray_cfg:
        return

    cfg_path = None
    proc     = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(xray_cfg, f)
            cfg_path = f.name

        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-config", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        time.sleep(XRAY_STARTUP_DELAY)
        if proc.poll() is not None:
            return

        r = requests.get(
            CHECK_URL,
            proxies={"http": f"socks5h://127.0.0.1:{socks_port}",
                     "https": f"socks5h://127.0.0.1:{socks_port}"},
            timeout=XRAY_HTTP_TIMEOUT,
            verify=False
        )
        if r.status_code >= 400:
            print(f"  XRAY FAIL {host} | HTTP {r.status_code}", flush=True)
            return

        # Конфиг рабочий — сохраняем
        print(f"  ✅ НАЙДЕН: {host} | {p}ms | {sni}", flush=True)
        with result_lock:
            if not stop_collecting.is_set():
                # Обновляем порт в конфиге на стандартный PROXY_SOCKS_PORT
                # (вторая джоба будет запускать их по одному на одном порту)
                xray_cfg['inbounds'][0]['port'] = PROXY_SOCKS_PORT
                found_configs.append({
                    "link":     link,
                    "xray_json": xray_cfg,
                    "ping":     p
                })
                print(f"  📦 Сохранено конфигов: {len(found_configs)}/{MAX_PROXY_CONFIGS}", flush=True)
                if len(found_configs) >= MAX_PROXY_CONFIGS:
                    stop_collecting.set()

    except requests.exceptions.Timeout:
        print(f"  XRAY TIMEOUT {host}", flush=True)
    except Exception as e:
        print(f"  XRAY ERR {host}: {e}", flush=True)
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=2)
            except: proc.kill()
        if cfg_path and os.path.exists(cfg_path):
            try: os.unlink(cfg_path)
            except: pass


def fetch_raw_configs(url):
    try:
        resp = session.get(url, timeout=7, verify=False).text
        if "://" not in resp[:50]:
            try: resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
            except: pass
        return [l.strip() for l in re.findall(r'(?:vless|ssr|tuic|hysteria|hysteria2)://[^\s]+', resp)]
    except:
        return []


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    print("--- 🔍 ПОИСК RU ПРОКСИ ---", flush=True)

    sni_domains = set()
    extra_urls, std_urls = [], []

    try:
        src_text = session.get(REMOTE_SOURCE_URL, timeout=10).text

        def get_list(var):
            m = re.search(rf'{var}\s*=\s*\[(.*?)\]', src_text, re.S | re.I)
            return re.findall(r'["\']([^"\']+)["\']', m.group(1)) if m else []

        extra_urls = get_list("EXTRA_URLS_FOR_26")
        std_urls   = get_list("URLS")
        sni_domains.update(s.lower() for s in get_list("SNI_DOMAINS"))

        sec = session.get(SECONDARY_WHITELIST_URL, timeout=10).text
        sni_domains.update(l.strip().lower() for l in sec.splitlines() if l.strip())
    except Exception as e:
        print(f"❌ Ошибка загрузки источников: {e}", flush=True)

    print(f"SNI доменов: {len(sni_domains)} | Extra: {len(extra_urls)} | Std: {len(std_urls)}", flush=True)

    # Сначала ищем в extra (они приоритетнее), потом в std
    all_urls = list(set(extra_urls)) + list(set(std_urls) - set(extra_urls))
    configs  = []
    for url in all_urls:
        configs.extend(fetch_raw_configs(url))
    configs = list(set(configs))
    random.shuffle(configs)
    print(f"Конфигов для проверки: {len(configs)}", flush=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(test_config, c, sni_domains) for c in configs]
        for f in concurrent.futures.as_completed(futures):
            if stop_collecting.is_set():
                ex.shutdown(wait=False, cancel_futures=True)
                break

    if not found_configs:
        print("❌ Рабочий RU прокси не найден!", flush=True)
        with open("proxy_found.txt", "w") as f:
            f.write("false")
        return

    # Сохраняем все найденные конфиги как JSON-массив
    # Вторая джоба будет пробовать их по очереди пока один не заработает
    proxy_list = [c['xray_json'] for c in found_configs]
    with open("proxy_configs.json", "w") as f:
        json.dump(proxy_list, f)

    with open("proxy_found.txt", "w") as f:
        f.write("true")

    print(f"✅ Сохранено {len(found_configs)} прокси-конфигов", flush=True)
    for i, c in enumerate(found_configs, 1):
        h = c['xray_json']['outbounds'][0]['settings']['vnext'][0]['address']
        print(f"  {i}. {h} | {c['ping']}ms", flush=True)
    print("--- ГОТОВО ---", flush=True)


if __name__ == "__main__":
    main()
    
