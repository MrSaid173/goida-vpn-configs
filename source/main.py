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

# --- ИНИЦИАЛИЗАЦИЯ ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
zone = zoneinfo.ZoneInfo("Europe/Moscow")
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")

g = Github(auth=Auth.Token(GITHUB_TOKEN)) if GITHUB_TOKEN else Github()
REPO = g.get_repo(REPO_NAME)

# --- УМНЫЙ ПАРСИНГ ДАННЫХ ---

def get_remote_data():
    """Парсит ссылки и SNI, подстраиваясь под изменения в исходном коде."""
    try:
        resp = requests.get(REMOTE_SOURCE_URL, timeout=15)
        resp.raise_for_status()
        code = resp.text

        # 1. Ищем все списки вида ИМЯ_ПЕРЕМЕННОЙ = [ ... ]
        all_lists = re.findall(r'(\w+)\s*=\s*\[(.*?)\]', code, re.DOTALL)
        
        std_urls = []
        extra_urls = []
        raw_sni_list = []

        for var_name, content in all_lists:
            # Вытягиваем все кавычки со ссылками или доменами
            items = re.findall(r'["\']([^"\']+)["\']', content)
            
            if var_name == "URLS":
                std_urls = items
            elif var_name == "EXTRA_URLS_FOR_26":
                extra_urls = items
            elif var_name == "SNI_DOMAINS":
                raw_sni_list = items
            # Если EXTRA еще не найдена, ищем список с GitHub ссылками
            elif not extra_urls and any("github" in item for item in items):
                print(f"🔍 Найдена замена EXTRA_URLS: переменная '{var_name}'")
                extra_urls = items

        # Фильтрация SNI: убираем всё, что содержит "vk"
        filtered_sni = [s for s in raw_sni_list if "vk" not in s.lower()]
        if filtered_sni:
            sni_regex = re.compile(r"(?:" + "|".join(re.escape(d) for d in filtered_sni) + r")")
        else:
            sni_regex = re.compile(r".*")

        return list(dict.fromkeys(extra_urls)), list(dict.fromkeys(std_urls)), sni_regex, len(filtered_sni)

    except Exception as e:
        print(f"❌ Ошибка парсинга: {e}")
        return [], [], re.compile(r".*"), 0

# --- ПРОВЕРКИ ---

def get_server_host(link):
    """Извлекает хост (IP или домен) из конфига."""
    try:
        if link.startswith("vmess://"):
            payload = link[8:]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            data = json.loads(base64.b64decode(payload).decode('utf-8'))
            return data.get('add')
        # Для vless, trojan и других
        match = re.search(r'@([^:/?#\s]+)', link)
        return match.group(1) if match else None
    except:
        return None

def is_literal_ip(host):
    """Проверяет, является ли строка чистым IP-адресом."""
    if not host: return False
    try:
        ipaddress.ip_address(host)
        return True
    except:
        return False

def is_russian_ip(ip, ru_cache, ok_cache):
    """Проверка GeoIP с задержкой 1.4с для обхода лимитов API (45 зап/мин)."""
    if ip in ru_cache: return True
    if ip in ok_cache: return False
    
    try:
        time.sleep(1.4) # Задержка для безопасности
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=5).json()
        if r.get("countryCode") == "RU":
            ru_cache.add(ip)
            return True
        ok_cache.add(ip)
    except:
        pass
    return False

def fetch_and_filter(url, sni_regex):
    """Скачивает конфиги и фильтрует по SNI."""
    try:
        resp = requests.get(url, timeout=15, verify=False)
        # Разбиваем на строки, если всё в кучу
        text = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', resp.text)
        valid = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.lower().startswith(EXCLUDE_PROTOCOLS): continue
            if sni_regex.search(line):
                valid.append(line)
        return valid
    except:
        return []

# --- ОСНОВНОЙ ЦИКЛ ---

def main():
    extra_src, std_src, sni_regex, sni_count = get_remote_data()
    print(f"✅ SNI загружено: {sni_count} (без VK)")
    print(f"🔗 Ссылки из приоритетных источников: {len(extra_src)}")
    print(f"🔗 Ссылки из обычных источников: {len(std_src)}")

    ru_ips, ok_ips = set(), set()
    final_list = []
    seen_hosts = set()

    def process_pool(urls, limit):
        added = 0
        pool_results = []
        # max_workers=5 достаточно, так как мы всё равно ограничены временем time.sleep
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(fetch_and_filter, u, sni_regex) for u in urls]
            for f in concurrent.futures.as_completed(futures):
                for config in f.result():
                    if added >= limit: break
                    
                    host = get_server_host(config)
                    # Фильтр: только уникальные IP (без доменов)
                    if not host or not is_literal_ip(host) or host in seen_hosts:
                        continue
                    
                    # Фильтр: не Россия
                    if is_russian_ip(host, ru_ips, ok_ips):
                        print(f"📍 Пропущен RU IP: {host}")
                        continue
                    
                    seen_hosts.add(host)
                    pool_results.append(config)
                    added += 1
        return pool_results

    # 1. Берем 150 (50%) из Extra/GitHub источников
    half = MAX_CONFIGS // 2
    print(f"📡 Обработка приоритетных ссылок (лимит {half})...")
    final_list.extend(process_pool(extra_src, half))

    # 2. Добираем остальное из стандартных URLS
    remaining = MAX_CONFIGS - len(final_list)
    if remaining > 0:
        print(f"📡 Добор {remaining} конфигов из общих источников...")
        final_list.extend(process_pool(std_src, remaining))

    # --- СОХРАНЕНИЕ ---
    unique_data = "\n".join(final_list)
    path = f"githubmirror/{FINAL_FILENAME}"

    try:
        try:
            curr = REPO.get_contents(path)
            REPO.update_file(path, f"🚀 Sync | {offset}", unique_data, curr.sha)
        except:
            REPO.create_file(path, f"🆕 Create | {offset}", unique_data)
        print(f"🏁 Финиш! Итого сохранено уникальных не-RU IP: {len(final_list)}")
    except Exception as e:
        print(f"❌ Ошибка GitHub: {e}")

if __name__ == "__main__":
    main()
