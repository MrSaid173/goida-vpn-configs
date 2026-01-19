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
REPO_NAME = "MrSaid173/goida-vpn-configs"
FINAL_FILENAME = "vlm"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
EXCLUDE_PROTOCOLS = ("ss://", "trojan://")
MAX_CONFIGS = 300
MAX_PER_SUBNET = 5 

# --- ИНИЦИАЛИЗАЦИЯ ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
zone = zoneinfo.ZoneInfo("Europe/Moscow")
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")

g = Github(auth=Auth.Token(GITHUB_TOKEN)) if GITHUB_TOKEN else Github()
REPO = g.get_repo(REPO_NAME)

# --- ПАРСИНГ ДАННЫХ ---

def get_remote_data():
    try:
        resp = requests.get(REMOTE_SOURCE_URL, timeout=15)
        resp.raise_for_status()
        code = resp.text
        
        # Ищем списки, игнорируя регистр букв в названии переменной
        all_lists = re.findall(r'(\w+)\s*=\s*\[(.*?)\]', code, re.DOTALL | re.IGNORECASE)
        
        std_urls, extra_urls, raw_sni_list = [], [], []
        for var_name, content in all_lists:
            v_upper = var_name.upper()
            items = re.findall(r'["\']([^"\']+)["\']', content)
            
            if v_upper == "URLS": std_urls = items
            elif v_upper == "EXTRA_URLS_FOR_26": extra_urls = items
            elif v_upper == "SNI_DOMAINS": raw_sni_list = items
            elif not extra_urls and any("github" in item for item in items): extra_urls = items

        # Фильтр VK (всегда в нижнем регистре для точности)
        filtered_sni = [s for s in raw_sni_list if "vk" not in s.lower()]
        
        if filtered_sni:
            sni_regex = re.compile(r"(?:" + "|".join(re.escape(d) for d in filtered_sni) + r")", re.IGNORECASE)
        else:
            # Если список пуст, разрешаем всё (твое пожелание)
            sni_regex = re.compile(r".*")

        return list(dict.fromkeys(extra_urls)), list(dict.fromkeys(std_urls)), sni_regex, len(filtered_sni)
    except Exception as e:
        print(f"❌ Ошибка парсинга: {e}")
        return [], [], re.compile(r".*"), 0

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

def is_russian_subnet(subnet, subnet_geo_cache):
    if subnet in subnet_geo_cache: return subnet_geo_cache[subnet]
    try:
        time.sleep(1.4)
        r = requests.get(f"http://ip-api.com/json/{subnet}.1?fields=countryCode", timeout=5).json()
        is_ru = (r.get("countryCode") == "RU")
        subnet_geo_cache[subnet] = is_ru
        return is_ru
    except: return False

def fetch_and_filter(url, sni_regex):
    try:
        resp = requests.get(url, timeout=15, verify=False)
        text = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', resp.text)
        valid = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.lower().startswith(EXCLUDE_PROTOCOLS): continue
            
            # Твои фильтры исключений
            low_line = line.lower()
            if "openproxy" in low_line or "vk" in low_line: continue
            
            if sni_regex.search(line):
                valid.append(line)
        return valid
    except: return []

def main():
    extra_src, std_src, sni_regex, sni_count = get_remote_data()
    print(f"✅ SNI загружено: {sni_count}. Ссылок: {len(extra_src)} приор., {len(std_src)} обыч.")

    final_list = []
    seen_hosts = set()
    subnet_counts = {}
    subnet_geo_cache = {}

    def process_pool(urls, limit):
        added = 0
        pool_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(fetch_and_filter, u, sni_regex) for u in urls]
            for f in concurrent.futures.as_completed(futures):
                for config in f.result():
                    if added >= limit: break
                    host = get_server_host(config)
                    if not host or not is_literal_ip(host) or host in seen_hosts: continue
                    
                    subnet = ".".join(host.split(".")[:3])
                    if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
                    if is_russian_subnet(subnet, subnet_geo_cache): continue
                    
                    seen_hosts.add(host)
                    subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                    pool_results.append(config)
                    added += 1
                    print(f"✅ [{len(final_list)+added}] Добавлен: {host}")
        return pool_results

    # 150 из приоритетных
    final_list.extend(process_pool(extra_src, MAX_CONFIGS // 2))

    # Добор до 300
    remaining = MAX_CONFIGS - len(final_list)
    if remaining > 0:
        final_list.extend(process_pool(std_src, remaining))

    # Сохранение
    unique_data = "\n".join(final_list)
    path = f"githubmirror/{FINAL_FILENAME}"
    try:
        try:
            curr = REPO.get_contents(path)
            REPO.update_file(path, f"🚀 Sync | {offset}", unique_data, curr.sha)
        except:
            REPO.create_file(path, f"🆕 Create | {offset}", unique_data)
        print(f"🏁 Финиш! Итого сохранено: {len(final_list)}")
    except Exception as e:
        print(f"❌ Ошибка GitHub: {e}")

if __name__ == "__main__":
    main()
    
