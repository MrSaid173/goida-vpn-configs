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

        filtered_sni = [s for s in raw_sni_list if "vk" not in s.lower()]
        sni_regex = re.compile(r"(?:" + "|".join(re.escape(d) for d in filtered_sni) + r")", re.IGNORECASE) if filtered_sni else re.compile(r".*")
        return list(dict.fromkeys(extra_urls)), list(dict.fromkeys(std_urls)), sni_regex
    except Exception as e:
        print(f"❌ Error: {e}")
        return [], [], re.compile(r".*")

# --- GEOIP ---
def is_russian_subnet(subnet, subnet_geo_cache):
    if subnet in subnet_geo_cache: return subnet_geo_cache[subnet]
    try:
        time.sleep(1.5)
        url = f"http://ip-api.com/json/{subnet}.1?fields=status,countryCode,isp,org,asname"
        r = session.get(url, timeout=5).json()
        if r.get("status") == "success":
            country = r.get("countryCode", "")
            info = (r.get("isp", "") + " " + r.get("org", "") + " " + r.get("asname", "")).lower()
            ru_keywords = ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota", "vimpelcom", "russia", "iot", "miran", "selectel"]
            is_ru = (country == "RU") or ("ru-" in info) or any(k in info for k in ru_keywords)
            if is_ru: print(f"🚩 Blocked RU: {subnet}.x | {info}")
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
        resp = session.get(url, timeout=15, verify=False)
        text = PROTO_RE.sub(r'\n\1://', resp.text)
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

    def process_links(urls):
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(fetch_and_filter, u, sni_regex) for u in urls]
            for f in concurrent.futures.as_completed(futures):
                for config in f.result():
                    if len(final_list) >= MAX_CONFIGS: return
                    host = get_server_host(config)
                    if not host or not is_literal_ip(host) or host in seen_hosts: continue
                    subnet = ".".join(host.split(".")[:3])
                    if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
                    if is_russian_subnet(subnet, subnet_geo_cache): continue
                    seen_hosts.add(host)
                    subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                    final_list.append(config)

    print("📡 Processing...")
    process_links(extra_src)
    if len(final_list) < MAX_CONFIGS:
        process_links(std_src)

    actual_count = len(final_list)
    unique_data = "\n".join(final_list)
    
    # --- УМНОЕ СОХРАНЕНИЕ (Force Push) ---
    try:
        path = f"githubmirror/{FINAL_FILENAME}"
        commit_msg = f"🚀 Latest Sync | {offset} | {actual_count} configs"
        
        # Обновляем файл конфигов
        try:
            curr_file = REPO.get_contents(path)
            REPO.update_file(path, commit_msg, unique_data, curr_file.sha)
        except:
            REPO.create_file(path, commit_msg, unique_data)
        
        # Обновляем README
        readme_path = "README.md"
        readme_content = f"# VPN Configs\n\n**Last Update:** {offset} (MSK)\n**Total Configs:** {actual_count}\n\n[Download VLM](https://github.com/{REPO_NAME}/raw/main/{path})"
        try:
            curr_readme = REPO.get_contents(readme_path)
            REPO.update_file(readme_path, "📝 Update Stats", readme_content, curr_readme.sha)
        except:
            REPO.create_file(readme_path, "🆕 Create README", readme_content)
            
        print(f"🏁 Successfully synced {actual_count} configs.")
    except Exception as e:
        print(f"❌ GitHub Error: {e}")

if __name__ == "__main__":
    main()
