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
            print(f"✅ [GitHub] Файл {path} успешно обновлен (SHA найден).")
        except Exception as e:
            print(f"ℹ️ [GitHub] Файл не найден или ошибка SHA ({e}). Пытаюсь создать заново...")
            REPO.create_file(path, msg, data)
            print(f"✅ [GitHub] Файл {path} создан.")
    except Exception as e:
        print(f"❌ [GitHub] Критическая ошибка: {e}")

def get_remote_data():
    print(f"🔍 [Parser] Загрузка данных из {REMOTE_SOURCE_URL}...")
    try:
        resp = session.get(REMOTE_SOURCE_URL, timeout=15)
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

        filtered_sni = [s for s in raw_sni_list if "vk" not in s.lower()]
        sni_regex = re.compile(r"(?:" + "|".join(re.escape(d) for d in filtered_sni) + r")", re.IGNORECASE) if filtered_sni else re.compile(r".*")
        print(f"📊 [Parser] Найдено SNI: {len(filtered_sni)}, Ссылок: {len(extra_urls)} приор., {len(std_urls)} обыч.")
        return list(dict.fromkeys(extra_urls)), list(dict.fromkeys(std_urls)), sni_regex
    except Exception as e:
        print(f"❌ [Parser] Ошибка: {e}")
        return [], [], re.compile(r".*")

def get_server_host(link):
    try:
        if link.startswith("vmess://"):
            payload = link[8:]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            return json.loads(base64.b64decode(payload).decode('utf-8')).get('add')
        match = re.search(r'@([^:/?#\s]+)', link)
        return match.group(1) if match else None
    except: return None

def fetch_and_filter(url, sni_regex):
    try:
        resp = session.get(url, timeout=10, verify=False)
        text = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', resp.text)
        valid = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.lower().startswith(EXCLUDE_PROTOCOLS): continue
            if "openproxy" in line.lower() or "vk" in line.lower(): continue
            if sni_regex.search(line): valid.append(line)
        return valid
    except: return []

def main():
    extra_src, std_src, sni_regex = get_remote_data()
    if not extra_src and not std_src:
        print("❌ [Main] Список источников пуст. Выход.")
        return

    print("📥 [Collector] Запуск многопоточного сбора конфигов...")
    all_raw = []
    combined_sources = extra_src + std_src
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futures = [ex.submit(fetch_and_filter, u, sni_regex) for u in combined_sources]
        for f in concurrent.futures.as_completed(futures): all_raw.extend(f.result())
    
    print(f"📦 [Collector] Всего собрано сырых строк: {len(all_raw)}")

    # Предварительный отбор по формату IP и подсетям
    candidates, seen_hosts, subnet_counts = [], set(), {}
    for cfg in all_raw:
        host = get_server_host(cfg)
        if not host or host in seen_hosts: continue
        try: 
            ipaddress.ip_address(host)
        except: 
            continue # Пропускаем домены

        subnet = ".".join(host.split(".")[:3])
        if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
        
        seen_hosts.add(host)
        subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
        candidates.append({"config": cfg, "ip": host})
    
    print(f"🎯 [Filter] Кандидатов на проверку GEO: {len(candidates)}")

    final_list = []
    ru_isps = ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota", "vimpelcom", "dataline", "selectel", "yandex", "it-grad", "miran", "russia"]

    # Пакетная проверка по 45 IP
    for i in range(0, len(candidates), 45):
        if len(final_list) >= MAX_CONFIGS: break
        batch = candidates[i : i + 45]
        print(f"📡 [API] Проверка пачки {i//45 + 1} ({len(batch)} IP)...")
        
        try:
            payload = [{"query": c["ip"], "fields": "status,countryCode,isp,org"} for c in batch]
            resp = session.post("http://ip-api.com/batch", json=payload, timeout=20)
            
            if resp.status_code == 200:
                results = resp.json()
                for item in results:
                    ip = item.get("query")
                    country = item.get("countryCode")
                    org_info = f"{item.get('isp', '')} {item.get('org', '')}".lower()
                    is_ru_isp = any(key in org_info for key in ru_isps)

                    if country != "RU" and not is_ru_isp:
                        # Ищем оригинальный конфиг для этого IP
                        cfg_data = next((x["config"] for x in batch if x["ip"] == ip), None)
                        if cfg_data: final_list.append(cfg_data)
                    else:
                        print(f"🚩 [Blocked] {ip} ({country} | {org_info})")
            else:
                print(f"⚠️ [API] Ошибка статуса {resp.status_code}. Пакет добавлен без проверки.")
                for c in batch: final_list.append(c["config"])

            print(f"📈 [Progress] Набрано: {len(final_list)}/{MAX_CONFIGS}")
            time.sleep(4.0) # Защита от бана
            
        except Exception as e:
            print(f"⚠️ [API] Ошибка запроса: {e}. Пакет пропущен (страховка).")
            for c in batch: final_list.append(c["config"])
            time.sleep(2)

    if final_list:
        final_list = final_list[:MAX_CONFIGS]
        update_gh(f"githubmirror/{FINAL_FILENAME}", f"🚀 Sync | {offset}", "\n".join(final_list))
        update_gh("README.md", "📝 Update", f"# VPN\n\n**Update:** {offset}\n**Total:** {len(final_list)}")
        print(f"🏁 [Done] Скрипт завершен. Итого: {len(final_list)}")
    else:
        print("❌ [Done] Конфиги не набраны.")

if __name__ == "__main__":
    main()
    
