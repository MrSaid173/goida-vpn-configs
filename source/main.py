import os, re, requests, urllib3, concurrent.futures, ipaddress, base64, json, time
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

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---

def get_server_host(link):
    try:
        if link.startswith("vmess://"):
            p = link[8:]; p += "=" * ((4 - len(p) % 4) % 4)
            return json.loads(base64.b64decode(p).decode('utf-8')).get('add')
        return (re.search(r'@([^:/?#\s]+)', link)).group(1)
    except: return None

def fetch_and_filter(url, sni_regex):
    try:
        resp = session.get(url, timeout=15, verify=False)
        text = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', resp.text)
        return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().lower().startswith(EXCLUDE_PROTOCOLS) and "openproxy" not in l.lower() and "vk" not in l.lower() and sni_regex.search(l)]
    except: return []

# --- ГЛАВНЫЙ ФИЛЬТР (BATCH) ---

def geo_filter_batch(candidates, current_count):
    """Самая быстрая и безопасная проверка GEO пачками"""
    final_checked = []
    # Расширенный список для блокировки
    ru_keys = ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota", "vimpelcom", "dataline", "selectel", "yandex", "vk cloud", "masterhost", "cloud.ru", "sbercloud", "timeweb", "hypercore", "vdsina", "russia"]
    
    for i in range(0, len(candidates), 45):
        if len(final_checked) + current_count >= MAX_CONFIGS: break
        batch = candidates[i : i + 45]
        print(f"📡 [API] Проверка пакета {i//45 + 1}...")
        
        try:
            payload = [{"query": c["ip"], "fields": "status,countryCode,isp,org"} for c in batch]
            resp = session.post("http://ip-api.com/batch", json=payload, timeout=20)
            
            if resp.status_code == 200:
                results = resp.json()
                api_map = {item['query']: item for item in results if item.get('status') == 'success'}
                
                for c in batch:
                    info = api_map.get(c["ip"])
                    if info:
                        country = info.get("countryCode", "")
                        org_info = f"{info.get('isp', '')} {info.get('org', '')}".lower()
                        is_ru = (country == "RU") or any(k in org_info for k in ru_keys)

                        if not is_ru:
                            final_checked.append(c["config"])
                            if len(final_checked) + current_count >= MAX_CONFIGS: break
                        else:
                            print(f"🚩 [Blocked] {c['ip']} ({country} | {org_info})")
            
            time.sleep(4.0) # Безопасная пауза между пачками
        except Exception as e:
            print(f"⚠️ Ошибка API: {e}. Пропускаем пачку.")
            
    return final_checked

# --- ОСНОВНАЯ ЛОГИКА ---

def main():
    print("🔍 [Parser] Получение ссылок и SNI...")
    try:
        resp = session.get(REMOTE_SOURCE_URL, timeout=15)
        all_lists = re.findall(r'(\w+)\s*=\s*\[(.*?)\]', resp.text, re.DOTALL | re.IGNORECASE)
        extra_urls, std_urls, raw_sni = [], [], []
        for name, content in all_lists:
            items = re.findall(r'["\']([^"\']+)["\']', content)
            if name.upper() == "URLS": std_urls = items
            elif name.upper() == "EXTRA_URLS_FOR_26": extra_urls = items
            elif name.upper() == "SNI_DOMAINS": raw_sni = items
        sni_regex = re.compile(r"(?:" + "|".join(re.escape(d) for d in raw_sni if "vk" not in d.lower()) + r")", re.IGNORECASE) if raw_sni else re.compile(r".*")
    except: return

    def get_candidates(urls):
        raw_configs = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            futures = [ex.submit(fetch_and_filter, u, sni_regex) for u in urls]
            for f in concurrent.futures.as_completed(futures): raw_configs.extend(f.result())
        
        clean = []
        seen_hosts, subnet_counts = set(), {}
        for cfg in raw_configs:
            host = get_server_host(cfg)
            if not host or host in seen_hosts: continue
            try: ipaddress.ip_address(host)
            except: continue
            
            subnet = ".".join(host.split(".")[:3])
            if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
            
            seen_hosts.add(host)
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
            clean.append({"config": cfg, "ip": host})
        return clean

    print("📥 [Collector] Сбор приоритетных источников...")
    cand_extra = get_candidates(extra_urls)
    final_list = geo_filter_batch(cand_extra, 0)

    if len(final_list) < MAX_CONFIGS:
        print(f"📡 [Collector] Добор из обычных источников (нужно еще {MAX_CONFIGS - len(final_list)})...")
        cand_std = get_candidates(std_urls)
        final_list.extend(geo_filter_batch(cand_std, len(final_list)))

    # --- СОХРАНЕНИЕ ---
    if final_list:
        content = "\n".join(final_list[:MAX_CONFIGS])
        try:
            path = f"githubmirror/{FINAL_FILENAME}"
            try:
                curr = REPO.get_contents(path)
                REPO.update_file(path, f"🚀 Sync | {offset}", content, curr.sha)
            except:
                REPO.create_file(path, f"🆕 Create | {offset}", content)
            
            # Обновление README для красоты
            REPO.update_file("README.md", "📝 Update stats", f"# VPN Mirror\n\n**Последнее обновление:** {offset}\n**Конфигов в списке:** {len(final_list[:MAX_CONFIGS])}", REPO.get_contents("README.md").sha)
            print(f"🏁 Успех! Сохранено {len(final_list[:MAX_CONFIGS])} конфигов.")
        except Exception as e:
            print(f"❌ Ошибка GitHub: {e}")

if __name__ == "__main__":
    main()
