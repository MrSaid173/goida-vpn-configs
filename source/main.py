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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")

g = Github(auth=Auth.Token(GITHUB_TOKEN)) if GITHUB_TOKEN else Github()
REPO = g.get_repo(REPO_NAME)

def update_gh(path, msg, data):
    print(f"📡 [GitHub] Попытка обновления {path}...")
    try:
        if isinstance(data, str): data = data.encode('utf-8')
        try:
            curr = REPO.get_contents(path)
            REPO.update_file(path, msg, data, curr.sha)
            print(f"✅ [GitHub] Файл {path} успешно обновлен.")
        except:
            REPO.create_file(path, msg, data)
            print(f"✅ [GitHub] Файл {path} создан.")
    except Exception as e:
        print(f"❌ [GitHub] Ошибка: {e}")

def get_remote_data():
    print(f"🔍 [Parser] Загрузка данных...")
    try:
        resp = session.get(REMOTE_SOURCE_URL, timeout=15)
        resp.raise_for_status()
        all_lists = re.findall(r'(\w+)\s*=\s*\[(.*?)\]', resp.text, re.DOTALL | re.IGNORECASE)
        
        std_urls, extra_urls, raw_sni_list = [], [], []
        for var_name, content in all_lists:
            items = re.findall(r'["\']([^"\']+)["\']', content)
            if var_name.upper() == "URLS": std_urls = items
            elif var_name.upper() == "EXTRA_URLS_FOR_26": extra_urls = items
            elif var_name.upper() == "SNI_DOMAINS": raw_sni_list = items

        filtered_sni = [s for s in raw_sni_list if "vk" not in s.lower()]
        sni_regex = re.compile(r"(?:" + "|".join(re.escape(d) for d in filtered_sni) + r")", re.IGNORECASE) if filtered_sni else re.compile(r".*")
        return extra_urls, std_urls, sni_regex
    except Exception as e:
        print(f"❌ [Parser] Ошибка: {e}")
        return [], [], re.compile(r".*")

def get_server_host(link):
    try:
        if link.startswith("vmess://"):
            p = link[8:]; p += "=" * ((4 - len(p) % 4) % 4)
            return json.loads(base64.b64decode(p).decode('utf-8')).get('add')
        return (re.search(r'@([^:/?#\s]+)', link)).group(1)
    except: return None

def fetch_and_filter(url, sni_regex):
    try:
        resp = session.get(url, timeout=10, verify=False)
        text = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', resp.text)
        return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().lower().startswith(EXCLUDE_PROTOCOLS) and "vk" not in l.lower() and sni_regex.search(l)]
    except: return []

def main():
    extra_src, std_src, sni_regex = get_remote_data()
    if not extra_src and not std_src: return

    print("📥 [Collector] Сбор конфигов...")
    all_raw = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futures = [ex.submit(fetch_and_filter, u, sni_regex) for u in (extra_src + std_src)]
        for f in concurrent.futures.as_completed(futures): all_raw.extend(f.result())
    
    candidates, seen_hosts, subnet_counts = [], set(), {}
    for cfg in all_raw:
        host = get_server_host(cfg)
        if not host or host in seen_hosts: continue
        try: ipaddress.ip_address(host)
        except: continue

        subnet = ".".join(host.split(".")[:3])
        if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
        seen_hosts.add(host)
        subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
        candidates.append({"config": cfg, "ip": host})
    
    print(f"🎯 [Filter] Кандидатов: {len(candidates)}")

    final_list = []
    # Чек-лист ключевых слов (теперь еще строже)
    ru_keys = ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota", "vimpelcom", "dataline", "selectel", "yandex", "it-grad", "miran", "russia", "vk cloud", "masterhost", "cloud.ru", "sbercloud", "timeweb", "hypercore", "rocketcloud", "baxet"]

    for i in range(0, len(candidates), 45):
        if len(final_list) >= MAX_CONFIGS: break
        batch = candidates[i : i + 45]
        print(f"📡 [API] Пакет {i//45 + 1}...")
        
        try:
            payload = [{"query": c["ip"], "fields": "status,countryCode,isp,org"} for c in batch]
            resp = session.post("http://ip-api.com/batch", json=payload, timeout=20)
            
            if resp.status_code == 200:
                for item in resp.json():
                    ip = item.get("query")
                    country = item.get("countryCode")
                    org_info = f"{item.get('isp', '')} {item.get('org', '')}".lower()
                    is_ru = (country == "RU") or any(k in org_info for k in ru_keys)

                    if not is_ru:
                        # ИСПРАВЛЕНО: Теперь ищем конфиг по IP корректно
                        for c in batch:
                            if c["ip"] == ip:
                                final_list.append(c["config"])
                                break
                    else:
                        print(f"🚩 [Blocked] {ip} ({country} | {org_info})")
            
            print(f"📈 [Progress] Набрано: {len(final_list)}/300")
            time.sleep(4.0)
            
        except Exception as e:
            print(f"⚠️ [API] Ошибка: {e}")
            for c in batch: final_list.append(c["config"])

    if final_list:
        update_gh(f"githubmirror/{FINAL_FILENAME}", f"🚀 Sync | {offset}", "\n".join(final_list[:MAX_CONFIGS]))
        update_gh("README.md", "📝 Update", f"# VPN\n\n**Update:** {offset}\n**Total:** {len(final_list[:MAX_CONFIGS])}")
        print(f"🏁 [Done] Итого: {len(final_list[:MAX_CONFIGS])}")

if __name__ == "__main__":
    main()
                
