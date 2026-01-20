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
MAX_CONFIGS = 200
MAX_PER_SUBNET = 3 
MAX_PER_SNI = 9
MAX_RU_CONFIGS = 5  # Оставляем ровно 5 RU

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

def get_config_sni(link):
    try:
        if link.startswith("vmess://"):
            payload = link[8:]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            data = json.loads(base64.b64decode(payload).decode('utf-8'))
            return data.get('sni') or data.get('host') or ""
        match = re.search(r'[?&](?:sni|host)=([^&#\s]+)', link)
        if match: return match.group(1).lower()
    except: pass
    return "no-sni"

def get_server_host(link):
    try:
        if link.startswith("vmess://"):
            payload = link[8:]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            data = json.loads(base64.b64decode(payload).decode('utf-8')).get('add')
            return data
        match = HOST_RE.search(link)
        return match.group(1) if match else None
    except: return None

def is_literal_ip(host):
    if not host: return False
    try:
        ipaddress.ip_address(host)
        return True
    except: return False

# --- GEOIP ---
def check_is_ru(subnet, subnet_geo_cache):
    if subnet in subnet_geo_cache: return subnet_geo_cache[subnet]
    try:
        time.sleep(1.2) # Оптимизировал задержку
        url = f"http://ip-api.com/json/{subnet}.1?fields=status,countryCode,isp,org,asname"
        r = session.get(url, timeout=5).json()
        if r.get("status") == "success":
            country = r.get("countryCode", "")
            info = (r.get("isp", "") + " " + r.get("org", "") + " " + r.get("asname", "")).lower()
            ru_keywords = ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota", "vimpelcom", "russia", "selectel", "gcore", "miran"]
            is_ru = (country == "RU") or any(k in info for k in ru_keywords)
            subnet_geo_cache[subnet] = is_ru
            return is_ru
    except: pass
    return False

# --- ПАРСИНГ ---
def get_remote_data():
    try:
        resp = session.get(REMOTE_SOURCE_URL, timeout=15)
        resp.raise_for_status()
        all_lists = VAR_RE.findall(resp.text)
        std_urls, extra_urls, raw_sni_list = [], [], []
        for var_name, content in all_lists:
            items = re.findall(r'["\']([^"\']+)["\']', content)
            if var_name.upper() == "URLS": std_urls = items
            elif var_name.upper() == "EXTRA_URLS_FOR_26": extra_urls = items
            elif var_name.upper() == "SNI_DOMAINS": raw_sni_list = items
        
        pattern = "|".join(re.escape(d) for d in raw_sni_list) if raw_sni_list else ".*"
        return list(dict.fromkeys(extra_urls)), list(dict.fromkeys(std_urls)), re.compile(pattern, re.I)
    except: return [], [], re.compile(".*")

def fetch_and_filter(url, sni_regex):
    try:
        resp = session.get(url, timeout=15, verify=False)
        text = PROTO_RE.sub(r'\n\1://', resp.text)
        valid = []
        for line in text.splitlines():
            line = line.strip()
            # УДАЛИЛ "russia" ИЗ ИСКЛЮЧЕНИЙ ТЕКСТА
            if not line or line.lower().startswith(EXCLUDE_PROTOCOLS) or "openproxy" in line.lower():
                continue
            if sni_regex.search(line):
                valid.append(line)
        return valid
    except: return []

# --- MAIN ---
def main():
    extra_src, std_src, sni_regex = get_remote_data()
    final_list, seen_hosts = [], set()
    subnet_counts, sni_counts, subnet_geo_cache = {}, {}, {}
    ru_count = 0 

    def process_links(urls):
        nonlocal ru_count
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(fetch_and_filter, u, sni_regex) for u in urls]
            for f in concurrent.futures.as_completed(futures):
                for config in f.result():
                    if len(final_list) >= MAX_CONFIGS: return
                    
                    host = get_server_host(config)
                    if not host or not is_literal_ip(host) or host in seen_hosts: continue
                    
                    sni = get_config_sni(config)
                    if sni_counts.get(sni, 0) >= MAX_PER_SNI: continue
                    
                    subnet = ".".join(host.split(".")[:3])
                    if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
                    
                    # Логика RU
                    is_ru = check_is_ru(subnet, subnet_geo_cache)
                    if is_ru:
                        if ru_count < MAX_RU_CONFIGS:
                            ru_count += 1
                            print(f"🇷🇺 [ALLOW] RU Server: {host} ({ru_count}/{MAX_RU_CONFIGS})")
                        else:
                            continue # Уже набрали 5 штук
                    
                    seen_hosts.add(host)
                    subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                    sni_counts[sni] = sni_counts.get(sni, 0) + 1
                    final_list.append(config)

    print("📡 Начинаю поиск (цель: 5 RU серверов)...")
    process_links(extra_src)
    if len(final_list) < MAX_CONFIGS:
        process_links(std_urls) # Исправлено имя переменной с std_src на std_urls если нужно

    # СОХРАНЕНИЕ
    if final_list:
        data = "\n".join(final_list)
        path = f"githubmirror/{FINAL_FILENAME}"
        try:
            curr = REPO.get_contents(path)
            REPO.update_file(path, f"🚀 Sync | RU:{ru_count}", data, curr.sha)
        except:
            REPO.create_file(path, f"🆕 Init | RU:{ru_count}", data)
        print(f"🏁 Готово! Набрано RU: {ru_count}. Всего: {len(final_list)}")

if __name__ == "__main__":
    main()
