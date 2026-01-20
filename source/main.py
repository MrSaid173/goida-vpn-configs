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
zone = zoneinfo.ZoneInfo("Europe/Moscow")
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")

g = Github(auth=Auth.Token(GITHUB_TOKEN)) if GITHUB_TOKEN else Github()
REPO = g.get_repo(REPO_NAME)

# --- ПАРСИНГ ---
def get_remote_data():
    try:
        resp = requests.get(REMOTE_SOURCE_URL, timeout=15)
        resp.raise_for_status()
        code = resp.text
        all_lists = re.findall(r'(\w+)\s*=\s*\[(.*?)\]', code, re.DOTALL | re.IGNORECASE)
        
        std_urls, extra_urls, raw_sni_list = [], [], []
        for var_name, content in all_lists:
            v_upper = var_name.upper()
            items = re.findall(r'["\']([^"\']+)["\']', content)
            if v_upper == "URLS": std_urls = items
            elif v_upper == "EXTRA_URLS_FOR_26": extra_urls = items
            elif v_upper == "SNI_DOMAINS": raw_sni_list = items
            elif not extra_urls and any("github" in item for item in items): extra_urls = items

        # filtered_sni = [s for s in raw_sni_list if "vk" not in s.lower()]
        sni_regex = filtered_sni
        return list(dict.fromkeys(extra_urls)), list(dict.fromkeys(std_urls)), sni_regex
    except Exception as e:
        print(f"❌ Ошибка парсинга: {e}")
        return [], [], re.compile(r".*")

# --- GEOIP ---
def is_russian_subnet(subnet, subnet_geo_cache):
    if subnet in subnet_geo_cache: return subnet_geo_cache[subnet]
    try:
        time.sleep(1.5) # Лимит ip-api.com
        url = f"http://ip-api.com/json/{subnet}.1?fields=status,countryCode,isp,org"
        r = requests.get(url, timeout=5).json()
        if r.get("status") == "success":
            info = (r.get("isp", "") + " " + r.get("org", "")).lower()
            is_ru = (r.get("countryCode") == "RU") or any(k in info for k in ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota", "vimpelcom", "russia"])
            subnet_geo_cache[subnet] = is_ru
            return is_ru
        return False
    except: return False

# --- ОБРАБОТКА ---
def get_server_host(link):
    try:
        if link.startswith("vmess://"):
            payload = link[8:]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            data = json.loads(base64.b64decode(payload).decode('utf-8'))
            return data.get('add')
        match = re.search(r'@([^:/?#\s]+)', link)
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
        resp = requests.get(url, timeout=15, verify=False)
        text = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', resp.text)
        valid = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.lower().startswith(EXCLUDE_PROTOCOLS): continue
            if "openproxy" in line.lower() or "russia" in line.lower(): continue
            if sni_regex.search(line): valid.append(line)
        return valid
    except: return []

# --- MAIN ---
def main():
    extra_src, std_src, sni_regex = get_remote_data()
    final_list, seen_hosts, subnet_counts, subnet_geo_cache = [], set(), {}, {}

    def add_configs(configs):
        for config in configs:
            if len(final_list) >= MAX_CONFIGS: return
            host = get_server_host(config)
            if not host or not is_literal_ip(host) or host in seen_hosts: continue
            subnet = ".".join(host.split(".")[:3])
            if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
            if is_russian_subnet(subnet, subnet_geo_cache): continue
            
            seen_hosts.add(host)
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
            final_list.append(config)

    print("📡 Сбор данных...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        # Сначала приоритетные
        f_extra = [executor.submit(fetch_and_filter, u, sni_regex) for u in extra_src]
        for f in concurrent.futures.as_completed(f_extra): add_configs(f.result())
        
        # Если не набрали - обычные
        if len(final_list) < MAX_CONFIGS:
            f_std = [executor.submit(fetch_and_filter, u, sni_regex) for u in std_src]
            for f in concurrent.futures.as_completed(f_std): add_configs(f.result())

    # --- СОХРАНЕНИЕ ---
    actual_count = len(final_list)
    unique_data = "\n".join(final_list)
    path = f"githubmirror/{FINAL_FILENAME}"
    
    try:
        try:
            curr = REPO.get_contents(path)
            REPO.update_file(path, f"🚀 Sync | {offset}", unique_data, curr.sha)
        except:
            REPO.create_file(path, f"🆕 Create | {offset}", unique_data)
        
        readme_text = f"# VPN Configs\n\nОбновлено: {offset} (МСК)\nКонфигов: {actual_count}\n\n[Скачать VLM](https://github.com/{REPO_NAME}/raw/main/{path})"
        rm = REPO.get_contents("README.md")
        REPO.update_file("README.md", "📝 Update README", readme_text, rm.sha)
        print(f"🏁 Финиш! Сохранено: {actual_count}")
    except Exception as e: print(f"❌ Ошибка GitHub: {e}")

if __name__ == "__main__":
    main()
