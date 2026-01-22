import os, re, requests, urllib3, concurrent.futures, ipaddress, json, time, socket, subprocess, zipfile
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
XRAY_BIN = "./xray"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MMDB_PATH = os.path.join(BASE_DIR, "GeoLite2-Country.mmdb")

EXCLUDE_PROTOCOLS = ("ss://", "trojan://", "vmess://")
MAX_CONFIGS = 150 
MAX_PER_SUBNET = 3 
MAX_RU_CONFIGS = 6
WORKERS = 30         # 30 одновременных тестов Xray
TEST_TIMEOUT = 1.0   # Таймаут теста 1 сек

COUNTRY_MAP = {
    "RU": ["russia", "россия", "rus"],
    "US": ["usa", "united states", "сша"],
    "DE": ["germany", "германия", "deutschland"],
    "NL": ["netherlands", "нидерланды", "holland"],
    "FI": ["finland", "финляндия"],
    "TR": ["turkey", "турция"],
    "KZ": ["kazakhstan", "казахстан"],
    "GB": ["united kingdom", "британ"],
    "FR": ["france", "франция"]
}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")

# --- СЛУЖЕБНЫЕ ФУНКЦИИ ---

def setup_xray():
    if os.path.exists(XRAY_BIN):
        if datetime.now() - datetime.fromtimestamp(os.path.getmtime(XRAY_BIN)) < timedelta(days=30): return True
        os.remove(XRAY_BIN)
    try:
        r = requests.get("https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip", timeout=15)
        with open("xray.zip", "wb") as f: f.write(r.content)
        with zipfile.ZipFile("xray.zip", 'r') as z: z.extract("xray", path=".")
        os.chmod(XRAY_BIN, 0o755)
        return True
    except: return False

def update_mmdb():
    if os.path.exists(MMDB_PATH) and datetime.now() - datetime.fromtimestamp(os.path.getmtime(MMDB_PATH)) < timedelta(days=3): return
    try:
        r = requests.get(MMDB_URL, timeout=30)
        with open(MMDB_PATH, "wb") as f: f.write(r.content)
    except: pass

def get_country_from_name(link):
    name = link.split("#")[-1].lower() if "#" in link else ""
    for iso, keywords in COUNTRY_MAP.items():
        if any(k in name for k in keywords): return iso
    return None

def test_xray_worker(vless_link, port):
    """Параллельный воркер: запускает Xray и делает запрос за 1 сек"""
    config_file = f"t_{port}.json"
    proc = None
    try:
        parts = vless_link.split("://")[1].split("#")[0].split("@")
        user_id = parts[0]
        addr_port = parts[1].split("?")[0].split(":")
        
        x_cfg = {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": port, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": addr_port[0], "port": int(addr_port[1]), "users": [{"id": user_id}]}]}}]
        }
        with open(config_file, "w") as f: json.dump(x_cfg, f)
        
        proc = subprocess.Popen([XRAY_BIN, "-c", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Проверка готовности порта (0.4 сек)
        start_p = time.time()
        ready = False
        while time.time() - start_p < 0.4:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(('127.0.0.1', port)) == 0:
                    ready = True; break
            time.sleep(0.05)
        
        if not ready: return False
        
        proxies = {'http': f'socks5h://127.0.0.1:{port}', 'https': f'socks5h://127.0.0.1:{port}'}
        r = session.get("http://www.gstatic.com/generate_204", proxies=proxies, timeout=TEST_TIMEOUT)
        return r.status_code == 204
    except: return False
    finally:
        if proc: proc.terminate(); proc.wait()
        if os.path.exists(config_file): os.remove(config_file)

def get_online_info(ip):
    """Лимитированный запрос к ip-api (1.35с) только для рабочих конфигов"""
    time.sleep(1.35)
    try:
        r = session.get(f"http://ip-api.com/json/{ip}?fields=status,countryCode,org,isp", timeout=3).json()
        if r.get("status") == "success":
            org = (r.get("org", "") + " " + r.get("isp", "")).lower()
            if "cloudflare" in org: return "CF", False
            is_ru = (r.get("countryCode") == "RU") or any(k in org for k in ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota"])
            return r.get("countryCode"), is_ru
    except: pass
    return None, False

# --- ГЛАВНАЯ ЛОГИКА ---

def main():
    if not setup_xray(): return
    update_mmdb()
    
    # Сбор ссылок
    try:
        resp = session.get(REMOTE_SOURCE_URL, timeout=10).text
        all_urls = re.findall(r'["\'](https?://[^"\']+)["\']', resp)
    except: return

    raw_configs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(lambda u: re.findall(r'vless://[^\s]+', session.get(u, timeout=10).text), u) for u in all_urls]
        for f in concurrent.futures.as_completed(futures):
            try: raw_configs.extend(f.result())
            except: pass
    
    raw_configs = list(set(raw_configs))
    vlm_list, vlm2_list = [], []
    seen_ips, subnet_counts, ru_count = set(), {}, 0

    

    with maxminddb.open_database(MMDB_PATH) as reader:
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
            tasks = {}
            for i, cfg in enumerate(raw_configs):
                try:
                    host = cfg.split("@")[1].split(":")[0]
                    ip = socket.gethostbyname(host)
                    subnet = ".".join(ip.split(".")[:3])
                    
                    if ip in seen_ips or subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
                    
                    # Быстрый фильтр MMDB
                    geo = reader.get(ip)
                    mmdb_iso = geo['country']['iso_code'] if geo and 'country' in geo else None
                    
                    name_iso = get_country_from_name(cfg)
                    if name_iso and mmdb_iso and name_iso != mmdb_iso: continue
                    
                    # Ставим в очередь на параллельный Xray тест
                    port = 21000 + (i % 500)
                    tasks[executor.submit(test_xray_worker, cfg, port)] = (cfg, ip, mmdb_iso, subnet)
                except: continue

            for f in concurrent.futures.as_completed(tasks):
                cfg, ip, mmdb_iso, subnet = tasks[f]
                if f.result(): # Если интернет есть
                    # Только теперь вызываем медленный ip-api
                    online_iso, is_ru = get_online_info(ip)
                    if online_iso == "CF": continue
                    
                    final_is_ru = is_ru or (mmdb_iso == "RU")
                    if final_is_ru:
                        if ru_count >= MAX_RU_CONFIGS: continue
                        ru_count += 1

                    vlm2_list.append(cfg)
                    if "xhttp" not in cfg.lower(): vlm_list.append(cfg)
                    
                    seen_ips.add(ip)
                    subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                    print(f" ✅ {ip} | {online_iso or mmdb_iso}")
                    
                    if len(vlm2_list) >= MAX_CONFIGS: break

    # Сохранение на GitHub
    if GITHUB_TOKEN:
        g = Github(auth=Auth.Token(GITHUB_TOKEN))
        repo = g.get_repo(REPO_NAME)
        for name, lst in [(FILENAME_VLM, vlm_list), (FILENAME_VLM2, vlm2_list)]:
            path = f"githubmirror/{name}"
            msg = f"🚀 {name} | T: {len(lst)} | RU: {ru_count} | {offset}"
            try:
                curr = repo.get_contents(path)
                repo.update_file(path, msg, "\n".join(lst), curr.sha)
            except: repo.create_file(path, msg, "\n".join(lst))

if __name__ == "__main__":
    main()
