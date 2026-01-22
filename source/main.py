import os, re, requests, urllib3, concurrent.futures, subprocess, json, time, socket, zipfile
from datetime import datetime
import zoneinfo
from github import Github, Auth

# --- НАСТРОЙКИ ---
XRAY_BIN = "./xray"
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MrSaid173/golden-paths_configs"
FILENAME_VLM2 = "vlm2"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"

MAX_CONFIGS = 150
MAX_PER_SUBNET = 3
MAX_RU_CONFIGS = 10 
WORKERS = 15

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
zone = zoneinfo.ZoneInfo("Europe/Moscow")
now_date = datetime.now(zone)
offset = now_date.strftime("%H:%M | %d.%m.%Y")

def get_xray_now():
    if os.path.exists(XRAY_BIN): return True
    try:
        url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
        r = requests.get(url, timeout=30)
        with open("xray.zip", "wb") as f: f.write(r.content)
        with zipfile.ZipFile("xray.zip", 'r') as zip_ref:
            zip_ref.extract("xray", path=".")
        os.chmod(XRAY_BIN, 0o755)
        os.remove("xray.zip")
        return True
    except: return False

def test_config_real(vless_link, local_port):
    config_file = f"config_{local_port}.json"
    proc = None
    try:
        # 1. Сверх-надежный парсинг
        if not vless_link.startswith("vless://"): return False, "NoVless"
        
        main_part = vless_link.split("://")[1].split("#")[0]
        if "@" not in main_part: return False, "ParseErr"
        
        user_info, rest = main_part.split("@")
        if "?" in rest:
            addr_port, params_raw = rest.split("?", 1)
            params = {k: v for k, v in [p.split("=") for p in params_raw.split("&") if "=" in p]}
        else:
            addr_port = rest
            params = {}
            
        if ":" not in addr_port: return False, "PortErr"
        address, port = addr_port.split(":")

        # 2. Конфиг Xray
        stream_settings = {"network": params.get("type", "tcp"), "security": params.get("security", "none")}
        if params.get("security") == "tls":
            stream_settings["tlsSettings"] = {"serverName": params.get("sni", address), "allowInsecure": True}
        elif params.get("security") == "reality":
            stream_settings["realitySettings"] = {
                "serverName": params.get("sni", address),
                "publicKey": params.get("pbk", ""),
                "shortId": params.get("sid", ""),
                "spiderX": params.get("spx", "")
            }

        xray_config = {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": local_port, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": address, "port": int(port), "users": [{"id": user_info, "encryption": "none", "flow": params.get("flow", "")}]}]},
                "streamSettings": stream_settings
            }]
        }

        with open(config_file, "w") as f: json.dump(xray_config, f)
        
        # 3. Запуск
        proc = subprocess.Popen([XRAY_BIN, "-c", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        if proc.poll() is not None: return False, "XrayCrash"

        # 4. Тест Cloudflare
        proxies = {'http': f'socks5://127.0.0.1:{local_port}', 'https': f'socks5://127.0.0.1:{local_port}'}
        r = requests.get("https://speed.cloudflare.com/meta", proxies=proxies, timeout=10)
        data = r.json()
        
        country = data.get("country", "??")
        if not country or country == "??": 
            # Запасной вариант если поле пустое
            country = data.get("region", "??")

        if ":" in data.get("clientIp", ""): return False, "IPv6"
        return True, country

    except: return False, "Error"
    finally:
        if proc:
            try: proc.terminate()
            except: pass
        if os.path.exists(config_file):
            try: os.remove(config_file)
            except: pass

def main():
    print(f"--- РЕСТАРТ ТЕСТА: {offset} ---")
    if not get_xray_now(): return
    
    auth = Auth.Token(GITHUB_TOKEN)
    g = Github(auth=auth)
    repo = g.get_repo(REPO_NAME)

    try:
        resp = requests.get(REMOTE_SOURCE_URL, timeout=15)
        sources = re.findall(r'["\'](https?://[^"\']+)["\']', resp.text)
        raw_configs = []
        for s in sources:
            try:
                r = requests.get(s, timeout=10)
                raw_configs.extend(re.findall(r'vless://[^\s]+', r.text))
            except: continue
        raw_configs = list(set(raw_configs))
        print(f"📦 Собрано уникальных: {len(raw_configs)}")
    except: return

    vlm2_list = []
    seen_ips, subnet_counts, ru_count = set(), {}, 0
    total = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = {executor.submit(test_config_real, cfg, 21000 + i): cfg for i, cfg in enumerate(raw_configs[:2000])}
        
        for f in concurrent.futures.as_completed(futures):
            total += 1
            cfg = futures[f]
            try:
                success, country = f.result()
            except: continue

            if not success:
                if total % 100 == 0: print(f" [LOG] {total} - {country}")
                continue

            # Фильтрация IP
            host_m = re.search(r'@([^:/?#\s]+)', cfg)
            if not host_m: continue
            ip_host = host_m.group(1)
            try:
                ip_addr = socket.gethostbyname(ip_host)
                subnet = ".".join(ip_addr.split(".")[:3])
            except: continue

            if ip_addr in seen_ips or subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET: continue

            if country == "RU":
                if ru_count >= MAX_RU_CONFIGS: continue
                ru_count += 1

            vlm2_list.append(cfg)
            seen_ips.add(ip_addr)
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
            print(f" ✅ ДОБАВЛЕН: {ip_addr} | {country} | RU: {ru_count}")

            if len(vlm2_list) >= MAX_CONFIGS: break

    # Сохранение
    if vlm2_list:
        path = f"githubmirror/{FILENAME_VLM2}"
        content = "\n".join(vlm2_list)
        msg = f"🚀 Update | Total: {len(vlm2_list)} | RU: {ru_count} | {offset}"
        try:
            sha = repo.get_contents(path).sha
            repo.update_file(path, msg, content, sha)
        except: repo.create_file(path, msg, content)
        print(f"🏁 Готово! Найдено: {len(vlm2_list)}")

if __name__ == "__main__":
    main()
