import os, re, requests, urllib3, concurrent.futures, subprocess, json, time, socket, signal
from datetime import datetime
import zoneinfo
from github import Github, Auth

# --- НАСТРОЙКИ ---
XRAY_BIN = "./xray"
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MrSaid173/golden-paths_configs"
FILENAME_VLM = "vlm"
FILENAME_VLM2 = "vlm2"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"

MAX_CONFIGS = 150
MAX_PER_SUBNET = 3
MAX_RU_CONFIGS = 10 
WORKERS = 35 # Максимальное ускорение

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
zone = zoneinfo.ZoneInfo("Europe/Moscow")
start_time = datetime.now(zone)
offset = start_time.strftime("%H:%M | %d.%m.%Y")

def test_config_real(vless_link, local_port):
    config_file = f"config_{local_port}.json"
    proc = None
    try:
        # Парсинг ссылки
        pattern = r"vless://([^@]+)@([^:]+):(\d+)\?([^#]+)"
        match = re.match(pattern, vless_link)
        if not match: return False, "ParseErr", 0
        
        uuid, address, port, params_str = match.groups()
        params = dict(re.findall(r'([^&=]+)=([^&]*)', params_str))
        
        # Минималистичный конфиг Xray для скорости
        xray_config = {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": local_port, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": address, "port": int(port), "users": [{"id": uuid, "encryption": "none", "flow": params.get("flow", "")}]}]},
                "streamSettings": {
                    "network": params.get("type", "tcp"),
                    "security": params.get("security", "none"),
                    "tlsSettings": {"serverName": params.get("sni", ""), "allowInsecure": True} if params.get("security") == "tls" else None,
                    "realitySettings": {
                        "serverName": params.get("sni", ""),
                        "publicKey": params.get("pbk", ""),
                        "shortId": params.get("sid", ""),
                        "spiderX": params.get("spx", "")
                    } if params.get("security") == "reality" else None,
                    "wsSettings": {"path": params.get("path", "/")} if params.get("type") == "ws" else None,
                    "grpcSettings": {"serviceName": params.get("serviceName", "")} if params.get("type") == "grpc" else None,
                }
            }]
        }

        with open(config_file, "w") as f: json.dump(xray_config, f)
        
        # Запуск Xray
        proc = subprocess.Popen([XRAY_BIN, "-c", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Оптимизированное ожидание старта
        time.sleep(0.6) 

        proxies = {"http": f"socks5h://127.0.0.1:{local_port}", "https": f"socks5h://127.0.0.1:{local_port}"}
        
        st = time.time()
        # Быстрый запрос к Cloudflare
        r = requests.get("https://speed.cloudflare.com/meta", proxies=proxies, timeout=4).json()
        latency = int((time.time() - st) * 1000)
        
        country = r.get("country", "??")
        client_ip = r.get("clientIp", "")
        
        # Проверка IPv6
        is_ipv6 = ":" in client_ip
        
        return (not is_ipv6), country, latency

    except:
        return False, "Fail", 0
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=0.5)
            except:
                proc.kill() # Если не хочет закрываться сам
        if os.path.exists(config_file):
            try: os.remove(config_file)
            except: pass

def main():
    g = Github(auth=Auth.Token(GITHUB_TOKEN)) if GITHUB_TOKEN else Github()
    REPO = g.get_repo(REPO_NAME)
    
    try:
        resp = requests.get(REMOTE_SOURCE_URL, timeout=15)
        urls = re.findall(r'["\'](https?://[^"\']+)["\']', resp.text)
    except: return

    raw_configs = []
    for u in urls:
        try:
            r = requests.get(u, timeout=10)
            raw_configs.extend(re.findall(r'vless://[^\s]+', r.text))
        except: continue

    raw_configs = list(set(raw_configs))
    vlm_list, vlm2_list = [], []
    seen_ips, subnet_counts, ru_count = set(), {}, 0

    print(f"🚀 Старт проверки {len(raw_configs)} конфигов в {WORKERS} потоков...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = {executor.submit(test_config_real, cfg, 20000 + i): cfg for i, cfg in enumerate(raw_configs)}
        
        for f in concurrent.futures.as_completed(futures):
            # Останавливаем обработку, если набрали максимум
            if len(vlm2_list) >= MAX_CONFIGS:
                break
                
            cfg = futures[f]
            try:
                is_ipv4, country, lat = f.result()
            except: continue
            
            if not is_ipv4 or country == "Fail": continue 
            
            host_m = re.search(r'@([^:/?#\s]+)', cfg)
            if not host_m: continue
            ip = host_m.group(1)
            
            try:
                # Резолвим IP для фильтрации подсетей
                ip_addr = socket.gethostbyname(ip) if not re.match(r'\d+\.', ip) else ip
                subnet = ".".join(ip_addr.split(".")[:3])
            except: continue

            if subnet in subnet_counts and subnet_counts[subnet] >= MAX_PER_SUBNET: continue
            if ip in seen_ips: continue

            is_ru = (country == "RU")
            if is_ru:
                if ru_count >= MAX_RU_CONFIGS: continue
                ru_count += 1

            vlm2_list.append(cfg)
            if "xhttp" not in cfg.lower():
                vlm_list.append(cfg)

            seen_ips.add(ip)
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
            print(f" [+] {ip[:15]:<15} | {lat:>4}ms | {country} | RU: {ru_count}")

    def save(name, lst):
        path = f"githubmirror/{name}"
        msg = f"🚀 {name} | Total: {len(lst)} | RU: {ru_count} | {offset}"
        try:
            sha = REPO.get_contents(path).sha
            REPO.update_file(path, msg, "\n".join(lst), sha)
        except:
            REPO.create_file(path, msg, "\n".join(lst))

    save(FILENAME_VLM, vlm_list)
    save(FILENAME_VLM2, vlm2_list)
    print(f"\n🏁 Готово! Время работы: {str(datetime.now(zone)-start_time).split('.')[0]}")

if __name__ == "__main__":
    main()
