import os
import re
import requests
import urllib3
import concurrent.futures
import ipaddress
import base64
import json
import time
import gzip
import shutil
import maxminddb
from datetime import datetime
import zoneinfo
from github import Github, Auth

# --- НАСТРОЙКИ ---
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MrSaid173/golden-paths_configs"
FINAL_FILENAME = "vlm"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
MAX_CONFIGS = 150
MAX_PER_SUBNET = 3
# Переносим базу в папку data
DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "dbip-country-lite.mmdb")
DB_URL = "https://download.db-ip.com/free/dbip-country-lite-{year}-{month}.mmdb.gz"

# --- ИНИЦИАЛИЗАЦИЯ ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")

g = Github(auth=Auth.Token(GITHUB_TOKEN)) if GITHUB_TOKEN else Github()
REPO = g.get_repo(REPO_NAME)

# --- 1. ЛОГИКА ОБНОВЛЕНИЯ И ХРАНЕНИЯ БАЗЫ ---
def sync_geoip_db():
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)

    now = datetime.now()
    
    # 1. Пытаемся взять базу из репозитория
    if not os.path.exists(DB_PATH):
        try:
            content = REPO.get_contents(DB_PATH)
            with open(DB_PATH, "wb") as f:
                f.write(content.decoded_content)
            print("📦 База скачана из репозитория в папку data/.")
        except:
            print("🐣 Базы в репозитории пока нет.")

    # 2. Проверяем нужно ли обновить (1-е число месяца или файл отсутствует)
    need_update = False
    if not os.path.exists(DB_PATH):
        need_update = True
    else:
        file_age_days = (time.time() - os.path.getmtime(DB_PATH)) / 86400
        if now.day == 1 or file_age_days > 31:
            need_update = True

    if need_update:
        print("🌐 Пытаемся скачать свежую базу...")
        url = DB_URL.format(year=now.year, month=f"{now.month:02d}")
        try:
            r = session.get(url, timeout=20)
            if r.status_code != 200:
                prev_m = now.month - 1 if now.month > 1 else 12
                prev_y = now.year if now.month > 1 else now.year - 1
                url = DB_URL.format(year=prev_y, month=f"{prev_m:02d}")
                r = session.get(url, timeout=20)

            if r.status_code == 200:
                gz_path = DB_PATH + ".gz"
                with open(gz_path, "wb") as f:
                    f.write(r.content)
                with gzip.open(gz_path, "rb") as f_in:
                    with open(DB_PATH, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)
                os.remove(gz_path)
                
                # Загружаем обновленную базу обратно в GitHub
                with open(DB_PATH, "rb") as f:
                    db_data = f.read()
                update_gh(DB_PATH, f"🔄 Update GeoIP DB {now.month}/{now.year}", db_data)
                print("✅ База обновлена и запушена в репо.")
        except Exception as e:
            print(f"⚠️ Ошибка обновления: {e}. Работаем на чем есть.")

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
def update_gh(path, msg, data):
    try:
        if isinstance(data, str): data = data.encode('utf-8')
        try:
            curr = REPO.get_contents(path)
            REPO.update_file(path, msg, data, curr.sha)
        except:
            REPO.create_file(path, msg, data)
    except Exception as e: print(f"❌ GH Error {path}: {e}")

def get_remote_data():
    try:
        resp = session.get(REMOTE_SOURCE_URL, timeout=10)
        all_lists = re.findall(r'(\w+)\s*=\s*\[(.*?)\]', resp.text, re.DOTALL | re.IGNORECASE)
        std_urls, extra_urls, raw_sni_list = [], [], []
        for var_name, content in all_lists:
            v_upper = var_name.upper()
            items = re.findall(r'["\']([^"\']+)["\']', content)
            if v_upper == "URLS": std_urls = items
            elif v_upper == "EXTRA_URLS_FOR_26": extra_urls = items
            elif v_upper == "SNI_DOMAINS": raw_sni_list = items
        sni_regex = re.compile(r"(?:" + "|".join(re.escape(d) for d in raw_sni_list) + r")", re.IGNORECASE) if raw_sni_list else re.compile(r".*")
        return list(dict.fromkeys(extra_urls + std_urls)), sni_regex
    except: return [], re.compile(r".*")

def get_server_host(link):
    try:
        if link.startswith("vmess://"):
            p = link[8:]; p += "=" * ((4 - len(p) % 4) % 4)
            return json.loads(base64.b64decode(p).decode('utf-8')).get('add')
        m = re.search(r'@([^:/?#\s]+)', link)
        return m.group(1) if m else None
    except: return None

def fetch_and_filter(url, sni_regex):
    try:
        r = session.get(url, timeout=5, verify=False)
        text = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', r.text)
        return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().lower().startswith(("ss://", "trojan://")) and sni_regex.search(l)]
    except: return []

# --- MAIN ---
def main():
    sync_geoip_db()
    
    sources, sni_regex = get_remote_data()
    if not sources: return

    print(f"📥 Сбор данных...")
    all_raw = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(fetch_and_filter, u, sni_regex) for u in sources]
        for f in concurrent.futures.as_completed(futures): all_raw.extend(f.result())

    candidates, seen_hosts, subnet_counts = [], set(), {}
    for config in all_raw:
        host = get_server_host(config)
        try: ipaddress.ip_address(host)
        except: continue
        if host in seen_hosts: continue
        subnet = ".".join(host.split(".")[:3])
        if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
        seen_hosts.add(host)
        subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
        candidates.append({"config": config, "ip": host})

    final_list = []
    waiting_list = []

    # ПЛАН А: Локально
    if os.path.exists(DB_PATH):
        try:
            with maxminddb.open_database(DB_PATH) as reader:
                for c in candidates:
                    res = reader.get(c["ip"])
                    if res and res.get('country') != "RU":
                        final_list.append(c["config"])
                        if len(final_list) >= MAX_CONFIGS: break
                    elif not res or 'country' not in res:
                        waiting_list.append(c)
        except: waiting_list = candidates
    else: waiting_list = candidates

    # ПЛАН Б: API
    if len(final_list) < MAX_CONFIGS and waiting_list:
        print(f"🔎 Добор через API ({MAX_CONFIGS - len(final_list)} шт)...")
        for i in range(0, len(waiting_list), 50):
            if len(final_list) >= MAX_CONFIGS: break
            batch = waiting_list[i : i + 50]
            try:
                payload = [{"query": c["ip"], "fields": "status,countryCode"} for c in batch]
                resp = session.post("http://ip-api.com/batch", json=payload, timeout=10)
                if resp.status_code == 200:
                    for item in resp.json():
                        if item.get("countryCode") != "RU":
                            # Находим конфиг для этого IP
                            cfg = next((x["config"] for x in batch if x["ip"] == item.get("query")), None)
                            if cfg:
                                final_list.append(cfg)
                                if len(final_list) >= MAX_CONFIGS: break
                time.sleep(2)
            except:
                for c in batch:
                    final_list.append(c["config"])
                    if len(final_list) >= MAX_CONFIGS: break

    if final_list:
        print(f"📤 Публикация...")
        readme = f"# VPN\n\n**Update:** {offset}\n**Total:** {len(final_list)}"
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            ex.submit(update_gh, f"githubmirror/{FINAL_FILENAME}", f"🚀 Sync {offset}", "\n".join(final_list))
            ex.submit(update_gh, "README.md", "📝 Update", readme)
    print("🏁 Готово.")

if __name__ == "__main__":
    main()
    
