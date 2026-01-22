import os, re, requests, urllib3, concurrent.futures, ipaddress, base64, json, time, socket, subprocess, zipfile
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
MMDB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "GeoLite2-Country.mmdb")

EXCLUDE_PROTOCOLS = ("ss://", "trojan://", "vmess://")
MAX_CONFIGS = 2 
MAX_PER_SUBNET = 1 
MAX_PER_SNI = 1
MAX_PER_ID = 1
MAX_RU_CONFIGS = 1
WORKERS = 15
TEST_TIMEOUT = 4.5  # Время на реальный тест интернета

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")

# --- ПОДГОТОВКА ИНСТРУМЕНТОВ ---

def setup_tools():
    if not os.path.exists(XRAY_BIN):
        print("📥 Скачивание ядра Xray...")
        r = requests.get("https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip", timeout=20)
        with open("xray.zip", "wb") as f: f.write(r.content)
        with zipfile.ZipFile("xray.zip", 'r') as z: z.extract("xray", path=".")
        os.chmod(XRAY_BIN, 0o755)
    
    if not os.path.exists(MMDB_PATH) or (datetime.now() - datetime.fromtimestamp(os.path.getmtime(MMDB_PATH)) > timedelta(days=3)):
        print("📥 Обновление GeoIP базы...")
        r = requests.get(MMDB_URL, timeout=30)
        with open(MMDB_PATH, "wb") as f: f.write(r.content)

# --- ПАРСИНГ И ОЧИСТКА ---

def fetch_and_clean_configs(url):
    try:
        resp = session.get(url, timeout=12, verify=False).text
        # Авто-декодирование Base64 (для LalatinaHub и др.)
        if "://" not in resp[:50] and len(resp) > 64:
            try:
                resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
            except: pass
        
        # Находим vless и чистим от ASCII мусора и эмодзи
        found = re.findall(r'vless://[^\s\'"]+', resp)
        cleaned = []
        for link in found:
            link = re.sub(r'[^\x20-\x7E]', '', link) # Только печатные символы
            if link.endswith(('.', ',', ';')): link = link[:-1]
            cleaned.append(link)
        return list(set(cleaned))
    except: return []

def get_config_details(link):
    try:
        parts = link.split("://")[1].split("#")[0]
        config_id = parts.split("@")[0]
        addr = parts.split("@")[1].split("?")[0].split(":")
        host, port = addr[0], int(addr[1])
        sni_m = re.search(r'[?&](?:sni|host)=([^&#\s]+)', link)
        sni = sni_m.group(1).lower() if sni_m else ""
        return host, port, sni, config_id
    except: return None, None, None, None

# --- ТЕСТИРОВАНИЕ ЧЕРЕЗ XRAY ---

def test_via_xray(vless_link, port):
    config_file = f"t_{port}.json"
    proc = None
    try:
        h, p, sni, cid = get_config_details(vless_link)
        # Генерируем временный конфиг для Xray
        x_cfg = {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": port, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": h, "port": p, "users": [{"id": cid}]}]}}]
        }
        with open(config_file, "w") as f: json.dump(x_cfg, f)
        
        # Запускаем Xray
        proc = subprocess.Popen([XRAY_BIN, "-c", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Ждем, пока порт откроется (макс 0.8с)
        ready = False
        for _ in range(8):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)
                if s.connect_ex(('127.0.0.1', port)) == 0:
                    ready = True; break
            time.sleep(0.1)
        
        if not ready: return False
        
        # Реальный запрос к Google через прокси
        proxies = {'http': f'socks5h://127.0.0.1:{port}', 'https': f'socks5h://127.0.0.1:{port}'}
        r = session.get("http://www.gstatic.com/generate_204", proxies=proxies, timeout=TEST_TIMEOUT)
        return r.status_code == 204
    except: return False
    finally:
        if proc:
            proc.terminate()
            try: proc.wait(timeout=1)
            except: proc.kill()
        if os.path.exists(config_file): os.remove(config_file)

# --- ГЛАВНАЯ ЛОГИКА ---

def main():
    setup_tools()
    
    print("🛰 Получение списков URL и SNI...")
    try:
        src_code = session.get(REMOTE_SOURCE_URL).text
        def extract_list(name):
            match = re.search(rf'{name}\s*=\s*\[(.*?)\]', src_code, re.S)
            return re.findall(r'["\'](https?://[^"\']+)["\']', match.group(1)) if match else []

        extra_urls = extract_list("EXTRA_URLS_FOR_26")
        std_urls = extract_list("URLS")
        
        sni_match = re.search(r'SNI_DOMAINS\s*=\s*\[(.*?)\]', src_code, re.S)
        sni_domains = [s.strip(" \"'") for s in sni_match.group(1).split(",")] if sni_match else []
    except Exception as e:
        print(f"❌ Ошибка загрузки источников: {e}"); return

    vlm_list, vlm2_list = [], []
    seen_ips, sni_counts, subnet_counts, id_counts = set(), {}, {}, {}
    ru_count = 0

    

    with maxminddb.open_database(MMDB_PATH) as reader:
        def process_stage(urls, use_sni_filter, stage_name):
            nonlocal ru_count
            print(f"\n--- ЭТАП: {stage_name} ({len(urls)} источников) ---")
            
            for u in urls:
                if len(vlm2_list) >= MAX_CONFIGS: break
                configs = fetch_and_clean_configs(u)
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
                    tasks = {}
                    for i, cfg in enumerate(configs):
                        if cfg.lower().startswith(EXCLUDE_PROTOCOLS): continue
                        
                        host, port, sni, cid = get_config_details(cfg)
                        if not host or host in seen_ips: continue
                        
                        # Фильтры (SNI, ID, Subnet)
                        if use_sni_filter and not any(d in sni for d in sni_domains): continue
                        if sni_counts.get(sni, 0) >= MAX_PER_SNI: continue
                        if id_counts.get(cid, 0) >= MAX_PER_ID: continue

                        try:
                            ip = socket.gethostbyname(host)
                            subnet = ".".join(ip.split(".")[:3])
                            if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
                            
                            geo = reader.get(ip)
                            is_ru = geo and geo.get('country', {}).get('iso_code') == 'RU'
                            if is_ru and ru_count >= MAX_RU_CONFIGS: continue
                            
                            # Предварительный пинг (быстрый сокет)
                            with socket.create_connection((ip, port), timeout=0.6):
                                t_port = 22000 + (i % 500)
                                tasks[executor.submit(test_via_xray, cfg, t_port)] = (cfg, ip, sni, subnet, cid, is_ru)
                        except: continue

                    for f in concurrent.futures.as_completed(tasks):
                        cfg, ip, sni, subnet, cid, is_ru = tasks[f]
                        if f.result():
                            if is_ru: ru_count += 1
                            vlm2_list.append(cfg)
                            if "xhttp" not in cfg.lower(): vlm_list.append(cfg)
                            
                            seen_ips.add(ip)
                            sni_counts[sni] = sni_counts.get(sni, 0) + 1
                            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                            id_counts[cid] = id_counts.get(cid, 0) + 1
                            print(f"  [+] {ip} | RU: {is_ru} | SNI: {sni}")
                            if len(vlm2_list) >= MAX_CONFIGS: return

        # Выполнение этапов
        process_stage(extra_urls, True, "EXTRA")
        process_stage(std_urls, True, "STD")
        process_stage(extra_urls + std_urls, False, "RESERVE")

    # --- СОХРАНЕНИЕ ---
    if GITHUB_TOKEN and (vlm_list or vlm2_list):
        g = Github(auth=Auth.Token(GITHUB_TOKEN))
        repo = g.get_repo(REPO_NAME)
        for name, lst in [(FILENAME_VLM, vlm_list), (FILENAME_VLM2, vlm2_list)]:
            path = f"githubmirror/{name}"
            content = "\n".join(lst)
            msg = f"🚀 {name} | Total: {len(lst)} | {offset}"
            try:
                sha = repo.get_contents(path).sha
                repo.update_file(path, msg, content, sha)
            except: repo.create_file(path, msg, content)
        print("💾 Обновлено на GitHub")

if __name__ == "__main__":
    main()
