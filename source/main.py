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
MAX_PER_SNI = 15
MAX_PER_ID = 3
MAX_RU_CONFIGS = 6
WORKERS = 15
TEST_TIMEOUT = 4.0 # Максимальное время ожидания ответа от Google

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")

# --- СЛУЖЕБНЫЕ ФУНКЦИИ ---

def setup_tools():
    if not os.path.exists(XRAY_BIN):
        try:
            r = requests.get("https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip", timeout=20)
            with open("xray.zip", "wb") as f: f.write(r.content)
            with zipfile.ZipFile("xray.zip", 'r') as z: z.extract("xray", path=".")
            os.chmod(XRAY_BIN, 0o755)
        except: pass
    if not os.path.exists(MMDB_PATH) or (datetime.now() - datetime.fromtimestamp(os.path.getmtime(MMDB_PATH)) > timedelta(days=3)):
        try:
            r = requests.get(MMDB_URL, timeout=30)
            with open(MMDB_PATH, "wb") as f: f.write(r.content)
        except: pass

def get_config_details(link):
    try:
        parts = link.split("://")[1].split("#")[0]
        config_id = parts.split("@")[0]
        host_port = parts.split("@")[1].split("?")[0].split(":")
        host = host_port[0]
        port = int(host_port[1])
        sni_match = re.search(r'[?&](?:sni|host)=([^&#\s]+)', link)
        sni = sni_match.group(1).lower() if sni_match else None
        return host, port, sni, config_id
    except: return None, None, None, None

def test_via_xray(vless_link, port):
    """Реальная проверка интернета через ядро Xray"""
    config_file = f"t_{port}.json"
    proc = None
    try:
        h, p, sni, cid = get_config_details(vless_link)
        x_cfg = {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": port, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": h, "port": p, "users": [{"id": cid}]}]}}]
        }
        with open(config_file, "w") as f: json.dump(x_cfg, f)
        proc = subprocess.Popen([XRAY_BIN, "-c", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Ожидание готовности порта (макс 0.8с)
        for _ in range(8):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(('127.0.0.1', port)) == 0: break
            time.sleep(0.1)
        
        proxies = {'http': f'socks5h://127.0.0.1:{port}', 'https': f'socks5h://127.0.0.1:{port}'}
        # Если ответ придет за 0.5с, функция завершится сразу
        r = session.get("http://www.gstatic.com/generate_204", proxies=proxies, timeout=TEST_TIMEOUT)
        return r.status_code == 204
    except: return False
    finally:
        if proc: proc.terminate(); proc.wait()
        if os.path.exists(config_file): os.remove(config_file)

def get_remote_data():
    try:
        resp = session.get(REMOTE_SOURCE_URL, timeout=15).text
        all_lists = re.findall(r'(\w+)\s*=\s*\[(.*?)\]', resp, re.DOTALL | re.IGNORECASE)
        std_src, extra_src, sni_list = [], [], []
        for var, content in all_lists:
            items = re.findall(r'["\']([^"\']+)["\']', content)
            if var.upper() == "URLS": std_src = items
            elif var.upper() == "EXTRA_URLS_FOR_26": extra_src = items
            elif var.upper() == "SNI_DOMAINS": sni_list = items
        return extra_src, std_src, sni_list
    except: return [], [], []

# --- ГЛАВНАЯ ЛОГИКА ---

def main():
    setup_tools()
    extra_urls, std_urls, sni_domains = get_remote_data()
    
    vlm_list, vlm2_list = [], []
    seen_ips = set()
    sni_counts, subnet_counts, id_counts = {}, {}, {}
    ru_count = 0

    

    with maxminddb.open_database(MMDB_PATH) as reader:
        
        def process_stage(urls, use_sni_filter, name):
            nonlocal ru_count
            print(f"--- ЭТАП: {name} ---")
            
            # Собираем все конфиги из списка URL
            raw_configs = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
                futures = [ex.submit(lambda u: re.findall(r'vless://[^\s]+', session.get(u, timeout=10).text), u) for u in urls]
                for f in concurrent.futures.as_completed(futures):
                    try: raw_configs.extend(f.result())
                    except: pass
            
            raw_configs = list(set(raw_configs))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
                tasks = {}
                for i, cfg in enumerate(raw_configs):
                    if len(vlm_list) >= MAX_CONFIGS and len(vlm2_list) >= MAX_CONFIGS: break
                    if cfg.lower().startswith(EXCLUDE_PROTOCOLS): continue
                    
                    host, port, sni, cid = get_config_details(cfg)
                    if not host or not sni or host in seen_ips: continue
                    
                    # Фильтры
                    if use_sni_filter and sni_domains and not any(d in sni for d in sni_domains): continue
                    if sni_counts.get(sni, 0) >= MAX_PER_SNI: continue
                    if id_counts.get(cid, 0) >= MAX_PER_ID: continue
                    
                    try:
                        ip = socket.gethostbyname(host)
                        subnet = ".".join(ip.split(".")[:3])
                        if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
                        
                        # Гео проверка
                        geo = reader.get(ip)
                        is_ru = geo and geo.get('country', {}).get('iso_code') == 'RU'
                        if is_ru and ru_count >= MAX_RU_CONFIGS: continue
                        
                        # Сначала быстрый пинг сокетом (0.5с), чтобы не мучать Xray
                        with socket.create_connection((ip, port), timeout=0.5):
                            t_port = 21000 + (i % 500)
                            tasks[executor.submit(test_via_xray, cfg, t_port)] = (cfg, ip, sni, subnet, cid, is_ru)
                    except: continue

                for f in concurrent.futures.as_completed(tasks):
                    cfg, ip, sni, subnet, cid, is_ru = tasks[f]
                    if f.result(): # Если Xray подтвердил интернет
                        if is_ru: ru_count += 1
                        
                        vlm2_list.append(cfg)
                        if "xhttp" not in cfg.lower(): vlm_list.append(cfg)
                        
                        seen_ips.add(ip)
                        sni_counts[sni] = sni_counts.get(sni, 0) + 1
                        subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                        id_counts[cid] = id_counts.get(cid, 0) + 1
                        print(f" [+] {ip} | RU: {is_ru} | SNI: {sni}")
                        
                        if len(vlm_list) >= MAX_CONFIGS: return

        # Выполнение этапов строго по порядку
        process_stage(extra_urls, True, "EXTRA")
        process_stage(std_urls, True, "STD")
        process_stage(extra_urls + std_urls, False, "RESERVE")

    # Сохранение на GitHub
    if GITHUB_TOKEN:
        g = Github(auth=Auth.Token(GITHUB_TOKEN))
        repo = g.get_repo(REPO_NAME)
        for name, lst in [(FILENAME_VLM, vlm_list), (FILENAME_VLM2, vlm2_list)]:
            path = f"githubmirror/{name}"
            content = "\n".join(lst)
            msg = f"🚀 {name} | T: {len(lst)} | {offset}"
            try:
                curr = repo.get_contents(path)
                repo.update_file(path, msg, content, curr.sha)
            except: repo.create_file(path, msg, content)

if __name__ == "__main__":
    main()
