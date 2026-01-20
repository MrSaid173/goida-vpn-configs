import os, re, requests, urllib3, concurrent.futures, ipaddress, base64, json, time, socket
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
MAX_RU_CONFIGS = 5

# --- ИНИЦИАЛИЗАЦИЯ ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
zone = zoneinfo.ZoneInfo("Europe/Moscow")
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")

# Безопасное подключение к GitHub
try:
    g = Github(auth=Auth.Token(GITHUB_TOKEN)) if GITHUB_TOKEN else Github()
    REPO = g.get_repo(REPO_NAME)
except Exception as e:
    print(f"❌ Ошибка подключения к GitHub: {e}")
    exit(1)

# --- ФУНКЦИИ ПРОВЕРКИ ---

def is_server_alive(host, port, timeout=2.0):
    """TCP Ping: проверяет, отвечает ли порт сервера."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False

def get_host_and_port(link):
    """Извлекает хост и порт для пинга."""
    try:
        if link.startswith("vmess://"):
            payload = link[8:]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            data = json.loads(base64.b64decode(payload).decode('utf-8'))
            return data.get('add'), int(data.get('port', 443))
        
        match = re.search(r'@([^:/?#\s]+):(\d+)', link)
        if match:
            return match.group(1), int(match.group(2))
    except: pass
    return None, None

def get_config_sni(link):
    """Извлекает SNI из параметров ссылки."""
    try:
        if link.startswith("vmess://"):
            payload = link[8:]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            data = json.loads(base64.b64decode(payload).decode('utf-8'))
            return data.get('sni') or data.get('host') or "no-sni"
        match = re.search(r'[?&](?:sni|host)=([^&#\s]+)', link)
        if match: return match.group(1).lower()
    except: pass
    return "no-sni"

def check_is_ru(subnet, cache):
    """Проверка GeoIP с кэшированием."""
    if subnet in cache: return cache[subnet]
    try:
        time.sleep(1.3) # Задержка для соблюдения лимитов ip-api.com
        url = f"http://ip-api.com/json/{subnet}.1?fields=status,countryCode,isp,org,asname"
        r = session.get(url, timeout=5).json()
        if r.get("status") == "success":
            info = (r.get("isp", "") + " " + r.get("org", "") + " " + r.get("asname", "")).lower()
            is_ru = (r.get("countryCode") == "RU") or any(k in info for k in ["mts", "beeline", "megafon", "rostelecom", "tele2", "yota", "vimpelcom", "russia", "selectel"])
            cache[subnet] = is_ru
            return is_ru
    except: pass
    return False

# --- ПАРСИНГ ---

def get_remote_data():
    try:
        resp = session.get(REMOTE_SOURCE_URL, timeout=15)
        resp.raise_for_status()
        code = resp.text
        all_lists = re.findall(r'(\w+)\s*=\s*\[(.*?)\]', code, re.DOTALL | re.IGNORECASE)
        
        std_src, extra_src, raw_sni_list = [], [], []
        for var_name, content in all_lists:
            items = re.findall(r'["\']([^"\']+)["\']', content)
            v_upper = var_name.upper()
            if v_upper == "URLS": std_src = items
            elif v_upper == "EXTRA_URLS_FOR_26": extra_src = items
            elif v_upper == "SNI_DOMAINS": raw_sni_list = items

        pattern = "|".join(re.escape(d) for d in raw_sni_list) if raw_sni_list else ".*"
        return list(dict.fromkeys(extra_src)), list(dict.fromkeys(std_src)), re.compile(pattern, re.I)
    except Exception as e:
        print(f"❌ Ошибка парсинга источника: {e}")
        return [], [], re.compile(".*")

def fetch_and_filter(url, sni_regex):
    try:
        resp = session.get(url, timeout=15, verify=False)
        # Разбиваем текст на строки по протоколам
        text = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', resp.text)
        valid = []
        for line in text.splitlines():
            line = line.strip()
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
        # Используем 25 потоков для быстрой проверки портов (TCP Ping)
        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
            futures = [executor.submit(fetch_and_filter, u, sni_regex) for u in urls]
            for f in concurrent.futures.as_completed(futures):
                for config in f.result():
                    if len(final_list) >= MAX_CONFIGS: return
                    
                    host, port = get_host_and_port(config)
                    if not host or host in seen_hosts: continue

                    # 1. TCP Ping (сначала проверяем, жив ли сервер)
                    if not is_server_alive(host, port):
                        continue

                    # 2. Фильтр SNI
                    sni = get_config_sni(config)
                    if sni_counts.get(sni, 0) >= MAX_PER_SNI: continue
                    
                    # 3. Фильтр подсети и GeoIP
                    try: ipaddress.ip_address(host)
                    except: continue
                    subnet = ".".join(host.split(".")[:3])
                    if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue
                    
                    is_ru = check_is_ru(subnet, subnet_geo_cache)
                    if is_ru:
                        if ru_count < MAX_RU_CONFIGS:
                            ru_count += 1
                            print(f"🇷🇺 [ALLOW RU] {host}:{port} ({ru_count}/{MAX_RU_CONFIGS})")
                        else:
                            continue # Пропускаем лишние RU

                    # Если все проверки пройдены
                    seen_hosts.add(host)
                    subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                    sni_counts[sni] = sni_counts.get(sni, 0) + 1
                    final_list.append(config)
                    print(f"✅ OK: {host}:{port} | SNI: {sni}")

    print(f"📡 Сбор конфигов (Цель RU: {MAX_RU_CONFIGS})...")
    
    # Сначала обрабатываем приоритетные ссылки
    process_links(extra_src)
    
    # Если не набрали лимит, добираем из обычных
    if len(final_list) < MAX_CONFIGS:
        process_links(std_src)

    # --- СОХРАНЕНИЕ ---
    actual_count = len(final_list)
    if actual_count > 0:
        unique_data = "\n".join(final_list)
        path = f"githubmirror/{FINAL_FILENAME}"
        commit_msg = f"🚀 Sync | RU:{ru_count} | Total:{actual_count} | {offset}"
        
        try:
            try:
                curr = REPO.get_contents(path)
                REPO.update_file(path, commit_msg, unique_data, curr.sha)
            except:
                REPO.create_file(path, commit_msg, unique_data)
            
            # Обновление README для статистики
            readme_text = f"# VPN Configs\n\nОбновлено: {offset} (МСК)\nВсего: {actual_count}\nРусских: {ru_count}\n\n[Список VLM](https://github.com/{REPO_NAME}/raw/main/{path})"
            rm = REPO.get_contents("README.md")
            REPO.update_file("README.md", "📝 Update README", readme_text, rm.sha)
            
            print(f"🏁 Завершено успешно! Сохранено: {actual_count}")
        except Exception as e:
            print(f"❌ Ошибка GitHub при сохранении: {e}")
    else:
        print("⚠️ Список пуст. Сохранять нечего.")

if __name__ == "__main__":
    main()
