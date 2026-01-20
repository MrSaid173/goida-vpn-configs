import os
import re
import requests
import urllib3
import concurrent.futures
import ipaddress
import base64
import json
import time
from datetime import datetime
import zoneinfo
from github import Github, Auth

# --- НАСТРОЙКИ ---
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MrSaid173/golden-paths_configs"
FINAL_FILENAME = "vlm"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
EXCLUDE_PROTOCOLS = ("ss://", "trojan://")
MAX_CONFIGS = 150
MAX_PER_SUBNET = 3 

# --- ИНИЦИАЛИЗАЦИЯ ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")

g = Github(auth=Auth.Token(GITHUB_TOKEN)) if GITHUB_TOKEN else Github()
REPO = g.get_repo(REPO_NAME)

VAR_RE = re.compile(r'(\w+)\s*=\s*\[(.*?)\]', re.DOTALL | re.IGNORECASE)
PROTO_RE = re.compile(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://')
HOST_RE = re.compile(r'@([^:/?#\s]+)')

# --- ПАРСИНГ ---
def get_remote_data():
    try:
        resp = session.get(REMOTE_SOURCE_URL, timeout=15)
        resp.raise_for_status()
        code = resp.text
        all_lists = VAR_RE.findall(code)
        
        std_urls, extra_urls, raw_sni_list = [], [], []
        for var_name, content in all_lists:
            v_upper = var_name.upper()
            items = re.findall(r'["\']([^"\']+)["\']', content)
            if v_upper == "URLS": std_urls = items
            elif v_upper == "EXTRA_URLS_FOR_26": extra_urls = items
            elif v_upper == "SNI_DOMAINS": raw_sni_list = items
            elif not extra_urls and any("github" in item for item in items): extra_urls = items

        sni_regex = re.compile(r"(?:" + "|".join(re.escape(d) for d in raw_sni_list) + r")", re.IGNORECASE) if raw_sni_list else re.compile(r".*")
        return list(dict.fromkeys(extra_urls + std_urls)), sni_regex
    except Exception as e:
        print(f"❌ Error getting remote data: {e}")
        return [], re.compile(r".*")

# --- GEOIP BATCH ---
def check_ips_batch(ips):
    """Проверяет список IP пачками по 100 штук через batch эндпоинт ip-api"""
    results = {}
    if not ips: return results
    
    # ip-api batch принимает до 100 объектов за раз
    for i in range(0, len(ips), 100):
        batch = ips[i:i+100]
        try:
            # Формируем список запросов для batch
            payload = [{"query": ip, "fields": "status,countryCode,isp,org,asname"} for ip in batch]
            resp = session.post("http://ip-api.com/batch", json=payload, timeout=20)
            if resp.status_code == 200:
                for item in resp.json():
                    ip = item.get("query")
                    country = item.get("countryCode", "")
                    info = (item.get("isp", "") + " " + item.get("org", "") + " " + item.get("asname", "")).lower()
                    ru_keywords = ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota", "vimpelcom", "russia", "iot", "miran", "selectel"]
                    is_ru = (country == "RU") or any(k in info for k in ru_keywords)
                    results[ip] = is_ru
            else:
                print(f"⚠️ Batch API returned status {resp.status_code}")
        except Exception as e:
            print(f"⚠️ Batch Error: {e}")
    return results

# --- ОБРАБОТКА ---
def get_server_host(link):
    try:
        if link.startswith("vmess://"):
            payload = link[8:]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            data = json.loads(base64.b64decode(payload).decode('utf-8'))
            return data.get('add')
        match = HOST_RE.search(link)
        return match.group(1) if match else None
    except: return None

def is_literal_ip(host):
    if not host: return False
    try:
        ipaddress.ip_address(host)
        return True
    except: return False

def fetch_and_filter(url, sni_regex):
    try:
        resp = session.get(url, timeout=12, verify=False)
        text = PROTO_RE.sub(r'\n\1://', resp.text)
        valid = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.lower().startswith(EXCLUDE_PROTOCOLS): continue
            if any(k in line.lower() for k in ["openproxy", "russia"]): continue
            if sni_regex.search(line): 
                valid.append(line)
        return valid
    except: return []

# --- MAIN ---
def main():
    all_sources, sni_regex = get_remote_data()
    if not all_sources: return

    # 1. Сбор всех сырых конфигов (Многопоточно)
    print(f"📥 Скачивание из {len(all_sources)} источников...")
    all_raw_configs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(fetch_and_filter, u, sni_regex) for u in all_sources]
        for f in concurrent.futures.as_completed(futures):
            all_raw_configs.extend(f.result())

    # 2. Первичная фильтрация (Текстовая + Подсети)
    print(f"🔍 Фильтрация кандидатов ({len(all_raw_configs)} шт)...")
    candidates = []
    seen_hosts = set()
    subnet_counts = {}

    for config in all_raw_configs:
        host = get_server_host(config)
        if not host or not is_literal_ip(host) or host in seen_hosts:
            continue
        
        subnet = ".".join(host.split(".")[:3])
        if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET:
            continue
            
        seen_hosts.add(host)
        subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
        candidates.append({"config": config, "ip": host})
        
        # Набираем с запасом (500), чтобы после GEO-фильтра точно осталось MAX_CONFIGS
        if len(candidates) >= 500: break

    # 3. Массовая проверка стран (Batch)
    print(f"🌍 Проверка GEO для {len(candidates)} IP...")
    unique_ips = [c["ip"] for c in candidates]
    geo_results = check_ips_batch(unique_ips)

    # 4. Финальный отбор
    final_list = []
    for c in candidates:
        is_ru = geo_results.get(c["ip"], False)
        if not is_ru:
            final_list.append(c["config"])
        if len(final_list) >= MAX_CONFIGS:
            break

    actual_count = len(final_list)
    unique_data = "\n".join(final_list)
    
    # --- СОХРАНЕНИЕ ---
    if not final_list:
        print("⚠ No configs found. Skip upload.")
        return

    try:
        path = f"githubmirror/{FINAL_FILENAME}"
        commit_msg = f"🚀 Sync | {offset} | {actual_count} configs"
        
        try:
            curr_file = REPO.get_contents(path)
            REPO.update_file(path, commit_msg, unique_data, curr_file.sha)
        except:
            REPO.create_file(path, commit_msg, unique_data)
        
        readme_content = f"# VPN Configs\n\n**Last Update:** {offset} (MSK)\n**Total Configs:** {actual_count}\n\n[Download VLM](https://github.com/{REPO_NAME}/raw/main/{path})"
        try:
            curr_readme = REPO.get_contents("README.md")
            REPO.update_file("README.md", "📝 Update Stats", readme_content, curr_readme.sha)
        except:
            REPO.create_file("README.md", "🆕 Create README", readme_content)
            
        print(f"🏁 Successfully synced {actual_count} configs.")
    except Exception as e:
        print(f"❌ GitHub Error: {e}")

if __name__ == "__main__":
    main()
    
