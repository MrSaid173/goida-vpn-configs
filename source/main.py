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
DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "dbip-country-lite.mmdb")
DB_URL = "https://download.db-ip.com/free/dbip-country-lite-{year}-{month}.mmdb.gz"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")

g = Github(auth=Auth.Token(GITHUB_TOKEN)) if GITHUB_TOKEN else Github()
REPO = g.get_repo(REPO_NAME)

def sync_geoip_db():
    if not os.path.exists(DB_DIR): os.makedirs(DB_DIR)
    now = datetime.now()
    if not os.path.exists(DB_PATH):
        try:
            content = REPO.get_contents(DB_PATH)
            with open(DB_PATH, "wb") as f: f.write(content.decoded_content)
            print("📦 База загружена из репо.")
        except: print("🐣 Базы в репо нет.")

    need_update = not os.path.exists(DB_PATH) or now.day == 1 or (time.time() - os.path.getmtime(DB_PATH)) / 86400 > 31
    if need_update:
        print("🌐 Обновление базы...")
        url = DB_URL.format(year=now.year, month=f"{now.month:02d}")
        try:
            r = session.get(url, timeout=20)
            if r.status_code != 200:
                prev_m, prev_y = (now.month-1, now.year) if now.month > 1 else (12, now.year-1)
                url = DB_URL.format(year=prev_y, month=f"{prev_m:02d}")
                r = session.get(url, timeout=20)
            if r.status_code == 200:
                with open(DB_PATH + ".gz", "wb") as f: f.write(r.content)
                with gzip.open(DB_PATH + ".gz", "rb") as f_in:
                    with open(DB_PATH, "wb") as f_out: shutil.copyfileobj(f_in, f_out)
                os.remove(DB_PATH + ".gz")
                with open(DB_PATH, "rb") as f: update_gh(DB_PATH, f"🔄 GeoIP Update {now.month}/{now.year}", f.read())
        except: pass

def update_gh(path, msg, data):
    try:
        if isinstance(data, str): data = data.encode('utf-8')
        try:
            curr = REPO.get_contents(path)
            REPO.update_file(path, msg, data, curr.sha)
        except: REPO.create_file(path, msg, data)
    except: pass

def get_remote_data():
    try:
        resp = session.get(REMOTE_SOURCE_URL, timeout=10)
        lists = re.findall(r'(\w+)\s*=\s*\[(.*?)\]', resp.text, re.DOTALL | re.IGNORECASE)
        urls, extra, snis = [], [], []
        for name, content in lists:
            items = re.findall(r'["\']([^"\']+)["\']', content)
            if name.upper() == "URLS": urls = items
            elif name.upper() == "EXTRA_URLS_FOR_26": extra = items
            elif name.upper() == "SNI_DOMAINS": snis = items
        regex = re.compile(r"(?:" + "|".join(re.escape(d) for d in snis) + r")", re.IGNORECASE) if snis else re.compile(r".*")
        return list(dict.fromkeys(extra + urls)), regex
    except: return [], re.compile(r".*")

def get_server_host(link):
    try:
        if link.startswith("vmess://"):
            p = link[8:]; p += "=" * ((4 - len(p) % 4) % 4)
            return json.loads(base64.b64decode(p).decode('utf-8')).get('add')
        m = re.search(r'@([^:/?#\s]+)', link)
        return m.group(1) if m else None
    except: return None

def fetch_and_filter(url, regex):
    try:
        r = session.get(url, timeout=5, verify=False)
        text = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', r.text)
        return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().lower().startswith(("ss://", "trojan://")) and regex.search(l)]
    except: return []

def main():
    sync_geoip_db()
    sources, sni_regex = get_remote_data()
    if not sources: return
    print("📥 Сбор данных...")
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

    final_list, waiting_list = [], []
    print(f"🌍 Локальный GEO-фильтр...")
    if os.path.exists(DB_PATH):
        try:
            with maxminddb.open_database(DB_PATH) as reader:
                for c in candidates:
                    res = reader.get(c["ip"])
                    if res and res.get('country') and res['country'] != "RU":
                        final_list.append(c["config"])
                        if len(final_list) >= MAX_CONFIGS: break
                    elif not res or not res.get('country'):
                        waiting_list.append(c)
        except: waiting_list = candidates
    else: waiting_list = candidates

    if len(final_list) < MAX_CONFIGS and waiting_list:
        print(f"🔎 Добор через API (нужно еще {MAX_CONFIGS - len(final_list)})...")
        ru_isps = ["dataline", "selectel", "m9", "petersburg", "moscow", "beeline", "mts", "megafon", "rostelecom", "yandex", "mail.ru", "miran", "it-grad", "vdsina"]
        
        for i in range(0, len(waiting_list), 50):
            if len(final_list) >= MAX_CONFIGS: break
            batch = waiting_list[i : i + 50]
            try:
                payload = [{"query": c["ip"], "fields": "status,countryCode,org,asname"} for c in batch]
                resp = session.post("http://ip-api.com/batch", json=payload, timeout=15)
                
                if resp.status_code == 200:
                    for item in resp.json():
                        ip = item.get("query")
                        country = item.get("countryCode")
                        org_info = f"{item.get('org', '')} {item.get('asname', '')}".lower()
                        is_ru_isp = any(isp in org_info for isp in ru_isps)
                        
                        # Если API ответило "RU" или это русский ISP — пропускаем
                        if country == "RU" or is_ru_isp:
                            continue
                        
                        # В остальных случаях (даже если ошибка в конкретной строке) — берем
                        cfg = next((x["config"] for x in batch if x["ip"] == ip), None)
                        if cfg:
                            final_list.append(cfg)
                            if len(final_list) >= MAX_CONFIGS: break
                else:
                    # Если всё API выдало ошибку (не 200), берем всю пачку (твоя страховка)
                    for c in batch:
                        final_list.append(c["config"])
                        if len(final_list) >= MAX_CONFIGS: break
                
                time.sleep(4.0) 
            except:
                # В случае любого сбоя — берем конфиги (страховка)
                for c in batch:
                    final_list.append(c["config"])
                    if len(final_list) >= MAX_CONFIGS: break
                time.sleep(2)

    if final_list:
        update_gh(f"githubmirror/{FINAL_FILENAME}", f"🚀 Sync {offset}", "\n".join(final_list))
        update_gh("README.md", "📝 Update", f"# VPN\n\n**Update:** {offset}\n**Total:** {len(final_list)}")
    print(f"🏁 Готово. Набрано {len(final_list)} конфигов.")

if __name__ == "__main__":
    main()
