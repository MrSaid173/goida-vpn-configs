import os, re, requests, urllib3, concurrent.futures, ipaddress, base64, json, time, socket, ssl, random
from datetime import datetime, timedelta
import zoneinfo
from github import Github, Auth
import threading

# --- НАСТРОЙКИ ---
GITHUB_TOKEN = os.environ.get("MY_TOKEN")
REPO_NAME = "MrSaid173/golden-paths_configs"
FILENAME_VLM = "vlm"
FILENAME_VLM2 = "vlm2"
REMOTE_SOURCE_URL = "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/source/main.py"
SECONDARY_WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt"

# --- ЛИМИТЫ ---
MIN_XHTTP = 1
MAX_XHTTP = 1
MIN_RU_CONFIGS = 5
MAX_RU_CONFIGS = 5
INTERLEAVE_STEP = 3
EXCLUDED_SNI_DOMAINS = ["userapi", "splitter.wb.ru"]
BAD_HOSTING_KEYWORDS = ["cloudflare", "hetzner", "digitalocean", "vultr", "amazon", "google", "microsoft", "ovh", "linode", "servers", "work", "oracle", "leaseweb", "m247", "akamai", "host"]
BANNED_ASNAME_PATTERNS = [
    "-ru", "-ua", "-by", "-kz", "-uz", "-ge", "-am", "-az", "-md", "-tj", "-kg", "-tm",
    "-us", "-ca", "-mx", "-br", "-ar", "-cl", "-co", "-pe", "-ve",
    "-de", "-nl", "-gb", "-uk", "-fr", "-it", "-es", "-pl", "-at", "-ch", "-se", "-no",
    "-fi", "-dk", "-ie", "-pt", "-be", "-cz", "-hu", "-ro", "-bg", "-gr", "-tr", "-ee",
    "-lv", "-lt", "-si", "-sk", "-hr", "-rs", "-me", "-ba", "-al", "-is", "-lu", "-mt",
    "-cn", "-hk", "-sg", "-jp", "-kr", "-in", "-tw", "-vn", "-th", "-my", "-ph", "-id",
    "-ae", "-il", "-sa", "-ir", "-iq", "-jo", "-kw", "-qa", "-om", "-ye",
    "-au", "-nz", "-za", "-ng", "-eg", "-ke", "-ma", "-dz", "-tn"
]
MAX_JITTER = 50
MAX_JITTER_RATIO = 0.4
MAX_CONFIGS = 50
MAX_TOTAL_SNI_RU = MAX_CONFIGS // 2
MAX_TOP_RU_SNI = 5
MAX_PER_COUNTRY = 15
MAX_PER_SUBNET = 3
MAX_PER_ID = 6
MAX_FAILED_PER_SUBNET = 4
MAX_EXPOSED_WORLD = 5
MAX_SAME_SNI_RU = 1
MAX_SAME_SNI_WORLD = 5
MIN_RU_PING, MAX_RU_PING = 90.0, 480.0
MIN_WORLD_PING, MAX_WORLD_PING = 25.0, 550.0
MAX_RU_PING_XHTTP = MAX_RU_PING + 120
MAX_WORLD_PING_XHTTP = MAX_WORLD_PING + 120

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
session.headers.update({'Connection': 'keep-alive'})
zone = zoneinfo.ZoneInfo("Europe/Moscow")
offset = datetime.now(zone).strftime("%H:%M | %d.%m.%Y")

COUNTRY_MAP = {
    "RU": {"aliases": ["RUSSIA", "РОССИЯ", "RUS", "🇷🇺"], "full": "Russia", "flag": "🇷🇺"},
    "US": {"aliases": ["USA", "UNITED STATES", "AMERICA", "🇺🇸"], "full": "USA", "flag": "🇺🇸"},
    "DE": {"aliases": ["GERMANY", "ГЕРМАНИЯ", "DEUTSCHLAND", "🇩🇪"], "full": "Germany", "flag": "🇩🇪"},
    "NL": {"aliases": ["NETHERLANDS", "НИДЕРЛАНДЫ", "HOLLAND", "🇳🇱"], "full": "The Netherlands", "flag": "🇳🇱"},
    "GB": {"aliases": ["UNITED KINGDOM", "ENGLAND", "🇬🇧"], "full": "United Kingdom", "flag": "🇬🇧"},
    "TR": {"aliases": ["TURKEY", "ТУРЦИЯ", "TURKIYE", "ТҮРКИЕ", "TÜRKIYE", "🇹🇷"], "full": "Turkey", "flag": "🇹🇷"},
    "KZ": {"aliases": ["KAZAKHSTAN", "КАЗАХСТАН", "🇰🇿"], "full": "Kazakhstan", "flag": "🇰🇿"},
    "FI": {"aliases": ["FINLAND", "ФИНЛЯНДИЯ", "🇫🇮"], "full": "Finland", "flag": "🇫🇮"},
    "PL": {"aliases": ["POLAND", "ПОЛЬША", "🇵🇱"], "full": "Poland", "flag": "🇵🇱"},
    "AT": {"aliases": ["AUSTRIA", "АВСТРИЯ", "🇦🇹"], "full": "Austria", "flag": "🇦🇹"},
    "LV": {"aliases": ["LATVIA", "ЛАТВИЯ", "🇱🇻"], "full": "Latvia", "flag": "🇱🇻"},
    "NO": {"aliases": ["NORWAY", "НОРВЕГИЯ", "🇳🇴"], "full": "Norway", "flag": "🇳🇴"},
    "SE": {"aliases": ["SWEDEN", "ШВЕЦИЯ", "🇸🇪"], "full": "Sweden", "flag": "🇸🇪"},
    "UA": {"aliases": ["UKRAINE", "УКРАИНА", "🇺🇦"], "full": "Ukraine", "flag": "🇺🇦"},
    "CA": {"aliases": ["CANADA", "КАНАДА", "🇨🇦"], "full": "Canada", "flag": "🇨🇦"},
    "CH": {"aliases": ["SWITZERLAND", "ШВЕЙЦАРИЯ", "🇨🇭"], "full": "Switzerland", "flag": "🇨🇭"},
    "CZ": {"aliases": ["CZECHIA", "CZECH REPUBLIC", "ЧЕХИЯ", "🇨🇿"], "full": "Czechia", "flag": "🇨🇿"},
    "IT": {"aliases": ["ITALY", "ИТАЛИЯ", "🇮🇹"], "full": "Italy", "flag": "🇮🇹"},
    "EE": {"aliases": ["ESTONIA", "ЭСТОНИЯ", "🇪🇪"], "full": "Estonia", "flag": "🇪🇪"},
    "FR": {"aliases": ["FRANCE", "ФРАНЦИЯ", "🇫🇷"], "full": "France", "flag": "🇫🇷"},
    "SG": {"aliases": ["SINGAPORE", "СИНГАПУР", "🇸🇬"], "full": "Singapore", "flag": "🇸🇬"},
    "BG": {"aliases": ["BULGARIA", "БОЛГАРИЯ", "🇧🇬"], "full": "Bulgaria", "flag": "🇧🇬"},
    "LT": {"aliases": ["LITHUANIA", "ЛИТВА", "🇱🇹"], "full": "Lithuania", "flag": "🇱🇹"},
    "BR": {"aliases": ["BRAZIL", "БРАЗИЛИЯ", "🇧🇷"], "full": "Brazil", "flag": "🇧🇷"},
    "JP": {"aliases": ["JAPAN", "ЯПОНИЯ", "🇯🇵"], "full": "Japan", "flag": "🇯🇵"},
    "IE": {"aliases": ["IRELAND", "ИРЛАНДИЯ", "🇮🇪"], "full": "Ireland", "flag": "🇮🇪"},
    "HK": {"aliases": ["HONG KONG", "ГОНКОНГ", "🇭🇰"], "full": "Hong Kong", "flag": "🇭🇰"},
    "IS": {"aliases": ["ICELAND", "ИСЛАНДИЯ", "🇮🇸"], "full": "Iceland", "flag": "🇮🇸"},
    "AL": {"aliases": ["ALBANIA", "АЛБАНИЯ", "🇦🇱"], "full": "Albania", "flag": "🇦🇱"},
    "CO": {"aliases": ["COLOMBIANA", "КОЛУМБИЯ", "🇨🇴"], "full": "Colombiana", "flag": "🇨🇴"},
    "MD": {"aliases": ["MOLDOVA", "МОВДОА", "🇲🇩"], "full": "Moldova", "flag": "🇲🇩"},
    "HU": {"aliases": ["HUNGARY", "ВЕНГРИЯ", "🇭🇺"], "full": "Hungary", "flag": "🇭🇺"},
    "ES": {"aliases": ["SPAIN", "ИСПАНИЯ", "🇪🇸"], "full": "Spain", "flag": "🇪🇸"},
    "IR": {"aliases": ["IRAN", "ИРАН", "🇮🇷"], "full": "Iran", "flag": "🇮🇷"},
    "KR": {"aliases": ["ROK", "KOREA", "ЮЖНАЯ КОРЕЯ", "🇰🇷"], "full": "South Korea", "flag": "🇰🇷"},
    "MY": {"aliases": ["MALAYSIA", "МАЛАЙЗИЯ", "🇲🇾"], "full": "Malaysia", "flag": "🇲🇾"},
    "AE": {"aliases": ["UAE", "UNITED ARAB EMIRATES", "ОАЭ", "🇦🇪"], "full": "UAE", "flag": "🇦🇪"},
}

lock = threading.Lock()
api_semaphore = threading.Semaphore(3)
stop_event = threading.Event()
ip_cache = {}
failed_subnets = {}
last_api_call = 0

# Статистика
total_processed = 0
total_links = 0
ping_failures = {"timeout": 0, "high": 0, "low": 0, "full_fail": 0}
ping_attempts_success = 0
ping_attempts_total = 0
country_mismatch = 0
ipapi_requests = 0
ipapi_failed = 0
dropped_by = {
    "broken": 0, "no_host_sni": 0, "seen_ips": 0, "sni_limit": 0,
    "subnet_limit": 0, "id_limit": 0, "failed_sub": 0, "exposed_world": 0,
    "xhttp_limit": 0, "ru_limit_vlm": 0, "ru_limit_vlm2": 0,
}
stages_passed = []

def fetch_raw_configs(url):
    global total_links
    try:
        resp = session.get(url, timeout=7, verify=False).text
        if "://" not in resp[:50]:
            try: resp = base64.b64decode(resp).decode('utf-8', errors='ignore')
            except: pass
        links = [l.strip() for l in re.findall(r'(?:vless|ssr|tuic|hysteria|hysteria2)://[^\s]+', resp) if not l.startswith(("ss://", "trojan://"))]
        total_links += len(links)
        return links
    except: return []

def validate(config, is_priority, is_white):
    global total_processed
    total_processed += 1
    nonlocal ru_vlm_count, ru_vlm2_count, xhttp_count
    if stop_event.is_set(): return

    is_xhttp = "xhttp" in config.lower()
    is_ru_potential = any(a in config.upper() for a in COUNTRY_MAP["RU"]["aliases"])

    with lock:
        if is_xhttp:
            if xhttp_count >= MAX_XHTTP:
                dropped_by["xhttp_limit"] += 1
                return
            if is_ru_potential and ru_vlm2_count >= MAX_RU_CONFIGS:
                dropped_by["ru_limit_vlm2"] += 1
                return
        else:
            vlm_needs_ru = is_ru_potential and ru_vlm_count < MAX_RU_CONFIGS
            vlm2_needs_ru = is_ru_potential and ru_vlm2_count < MAX_RU_CONFIGS
            vlm_full = len(vlm_results) >= MAX_CONFIGS
            vlm2_full = len(vlm2_results) >= MAX_CONFIGS
            if not (vlm_needs_ru or vlm2_needs_ru or not vlm_full or not vlm2_full):
                return

    if is_technically_broken(config):
        dropped_by["broken"] += 1
        return

    host, port, sni, cid, name = get_config_details(config)
    if not host or not sni:
        dropped_by["no_host_sni"] += 1
        return

    exp_tag = get_exposed_tag(host)

    if not is_white and exp_tag:
        with lock:
            if exposed_world_count >= MAX_EXPOSED_WORLD:
                dropped_by["exposed_world"] += 1
                return

    with lock:
        if host in seen_ips:
            dropped_by["seen_ips"] += 1
            return
        if (sni in sni_domains) != is_white:
            dropped_by["sni_limit"] += 1
            return
        if any(exc in sni for exc in EXCLUDED_SNI_DOMAINS):
            dropped_by["sni_limit"] += 1
            return
        sni_limit = MAX_SAME_SNI_RU if (is_ru_potential and is_white) else MAX_SAME_SNI_WORLD
        if sni_usage_counts.get(sni, 0) >= sni_limit:
            dropped_by["sni_limit"] += 1
            return
        subnet = ".".join(host.split(".")[:3])
        if subnet_counts.get(subnet, 0) >= MAX_PER_SUBNET:
            dropped_by["subnet_limit"] += 1
            return
        if id_counts.get(cid, 0) >= MAX_PER_ID:
            dropped_by["id_limit"] += 1
            return
        if failed_subnets.get(subnet, 0) >= MAX_FAILED_PER_SUBNET:
            dropped_by["failed_sub"] += 1
            return

    p1 = fast_ping(host, port, sni)

    if is_ru_potential:
        min_p = MIN_RU_PING
        max_p = MAX_RU_PING_XHTTP if is_xhttp else MAX_RU_PING
    else:
        min_p = MIN_WORLD_PING
        max_p = MAX_WORLD_PING_XHTTP if is_xhttp else MAX_WORLD_PING

    if not p1 or p1 > max_p:
        with lock:
            failed_subnets[subnet] = failed_subnets.get(subnet, 0) + 1
        ping_failures["timeout" if not p1 else "high"] += 1
        return
    ping_attempts_success += 1
    ping_attempts_total += 1
    if p1 < min_p:
        ping_failures["low"] += 1
        return

    ip_cc, ip_isp, ip_h_stat = check_isp_info(host)
    if not ip_cc or ip_h_stat == "BANNED" or stop_event.is_set():
        return

    is_ru = (ip_cc == "RU")
    if is_ru != is_ru_potential:
        country_mismatch += 1
        return

    full = full_ping_analysis(host, port, sni, p1)
    if not full or full[1] > MAX_JITTER:
        ping_failures["full_fail"] += 1
        return

    avg_ping = full[0]
    if avg_ping < min_p or avg_ping > max_p:
        ping_failures["full_fail"] += 1
        return

    with lock:
        if host in seen_ips:
            dropped_by["seen_ips"] += 1
            return
        res_entry = {
            "link": apply_clean_params(config),
            "ping": full[0],
            "country": ip_cc,
            "is_priority": is_priority,
            "white_sni": is_white,
            "is_hosting": ip_h_stat,
            "is_xhttp": is_xhttp,
            "exp_tag": exp_tag
        }
        added_vlm = added_vlm2 = False
        if is_xhttp:
            if is_ru:
                if ru_vlm2_count < MAX_RU_CONFIGS and xhttp_count < MAX_XHTTP:
                    vlm2_results.append(res_entry)
                    ru_vlm2_count += 1
                    xhttp_count += 1
                    added_vlm2 = True
            else:
                if xhttp_count < MAX_XHTTP:
                    vlm2_results.append(res_entry)
                    xhttp_count += 1
                    added_vlm2 = True
        else:
            if is_ru:
                if ru_vlm_count < MAX_RU_CONFIGS:
                    vlm_results.append(res_entry)
                    ru_vlm_count += 1
                    added_vlm = True
            elif len(vlm_results) < MAX_CONFIGS:
                vlm_results.append(res_entry)
                added_vlm = True
            if is_ru:
                if ru_vlm2_count < MAX_RU_CONFIGS:
                    vlm2_results.append(res_entry)
                    ru_vlm2_count += 1
                    added_vlm2 = True
            elif len(vlm2_results) < (MAX_CONFIGS - max(0, MIN_XHTTP - xhttp_count)):
                vlm2_results.append(res_entry)
                added_vlm2 = True

        if added_vlm or added_vlm2:
            seen_ips.add(host)
            sni_usage_counts[sni] = sni_usage_counts.get(sni, 0) + 1
            if not is_ru:
                country_counts[ip_cc] = country_counts.get(ip_cc, 0) + 1
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
            id_counts[cid] = id_counts.get(cid, 0) + 1
            print(f"[FOUND{' (X)' if is_xhttp else ''}] {ip_cc} | {full[0]}ms | {host}", flush=True)
            if not is_ru and exp_tag:
                exposed_world_count += 1

        if ru_vlm_count >= MIN_RU_CONFIGS and ru_vlm2_count >= MIN_RU_CONFIGS and xhttp_count >= MIN_XHTTP and len(vlm_results) >= MAX_CONFIGS:
            stop_event.set()

def fetch_group_data(urls):
    global total_links
    raw = []
    urls = list(set(urls))
    print(f"[FETCH] Обрабатываем {len(urls)} источников")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(fetch_raw_configs, u): u for u in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                links = future.result()
                raw.extend(links)
                print(f"[FETCH] Из {url} получено {len(links)} конфигов")
                total_links += len(links)
            except Exception as e:
                print(f"[FETCH ERROR] {url}: {e}")
    unique = list(set(raw))
    random.shuffle(unique)
    print(f"[FETCH] Уникальных конфигов: {len(unique)}")
    return unique

def main():
    global total_processed, stages_passed
    start_total = time.perf_counter()
    print(f"--- 🟢 ЗАПУСК [{offset}] ---", flush=True)

    sni_domains = set()
    exposed_world_count = 0
    extra_urls, std_urls, gh_repo = [], [], None
    try: gh_repo = Github(auth=Auth.Token(GITHUB_TOKEN)).get_repo(REPO_NAME)
    except: pass

    try:
        src_text = session.get(REMOTE_SOURCE_URL, timeout=10).text
        def get_list(var):
            m = re.search(rf'{var}\s*=\s*\[(.*?)\]', src_text, re.S | re.I)
            return re.findall(r'["\']([^"\']+)["\']', m.group(1)) if m else []
        extra_urls = get_list("EXTRA_URLS_FOR_26")
        std_urls = get_list("URLS")
        sni_domains.update(s.lower() for s in get_list("SNI_DOMAINS"))
        sec_text = session.get(SECONDARY_WHITELIST_URL, timeout=10).text
        sni_domains.update([l.strip().lower() for l in sec_text.splitlines() if l.strip()])
    except: pass

    vlm_results, vlm2_results = [], []
    seen_ips, subnet_counts, id_counts, country_counts = set(), {}, {}, {}
    sni_usage_counts = {}
    ru_vlm_count = ru_vlm2_count = xhttp_count = 0

    raw_extra, raw_std = fetch_group_data(extra_urls), fetch_group_data(std_urls)
    check_order = [(raw_extra, True, True), (raw_std, False, True), (raw_extra, True, False), (raw_std, False, False)]
    stage_names = ["extra + white", "std + white", "extra + non-white", "std + non-white"]

    for idx, (group, priority, white) in enumerate(check_order):
        if stop_event.is_set(): break
        stages_passed.append(stage_names[idx])
        workers = min(len(group), 40) if group else 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as v:
            for c in group:
                if stop_event.is_set(): break
                v.submit(validate, c, priority, white)

    def finalize_list(results, is_vlm2=False):
        all_ru_sni = sorted([r for r in results if r['country'] == 'RU' and r['white_sni']], key=lambda x: x['ping'])
        top_fixed = all_ru_sni[:MAX_TOP_RU_SNI]
        remaining_ru_sni = all_ru_sni[MAX_TOP_RU_SNI:]

        xhttp_bucket = []
        if is_vlm2:
            xhttp_bucket = sorted([r for r in results if r.get('is_xhttp')], key=lambda x: x['ping'])

        buckets = {i: [] for i in range(4)}
        for r in results:
            if r in top_fixed or r in xhttp_bucket or (r['country'] == 'RU' and r['white_sni']): continue
            b_idx = (0 if r['white_sni'] else 1) if r['is_priority'] else (2 if r['white_sni'] else 3)
            buckets[b_idx].append(r)

        for i in range(4): buckets[i].sort(key=lambda x: x['ping'])

        final = list(top_fixed)
        current_ru_sni_total = len(top_fixed)

        sources_order = []
        if is_vlm2: sources_order.append(xhttp_bucket)
        sources_order.append(buckets[0])
        sources_order.append(remaining_ru_sni)
        sources_order.append(buckets[2])
        sources_order.append(buckets[1])
        sources_order.append(buckets[3])

        while len(final) < MAX_CONFIGS:
            added_any = False
            for src in sources_order:
                is_sni_ru_src = (src is remaining_ru_sni or src is buckets[0] or src is buckets[2])
                count = 0
                while count < INTERLEAVE_STEP and len(final) < MAX_CONFIGS and src:
                    if is_sni_ru_src and current_ru_sni_total >= MAX_TOTAL_SNI_RU: break
                    config = src.pop(0)
                    if config not in final:
                        final.append(config)
                        count += 1; added_any = True
                        if is_sni_ru_src: current_ru_sni_total += 1
            if not added_any: break

        speed_rating = {r['link']: rank + 1 for rank, r in enumerate(sorted(final, key=lambda x: x['ping']))}
        return [rename_config(r['link'], r['country'], speed_rating[r['link']], r['is_hosting'], r['white_sni'], r.get('exp_tag')) for r in final]

    if gh_repo:
        for fn, res in [(FILENAME_VLM, vlm_results), (FILENAME_VLM2, vlm2_results)]:
            output = finalize_list(res, is_vlm2=(fn == FILENAME_VLM2))
            path, content = f"githubmirror/{fn}", "\n".join(output)
            try:
                sha = gh_repo.get_contents(path).sha
                gh_repo.update_file(path, f"🚀 {fn} | {len(output)} | {offset}", content, sha)
            except: gh_repo.create_file(path, f"🚀 {fn} | {len(output)} | {offset}", content)

    print("\n" + "="*50)
    print("📊 СТАТИСТИКА ЗАПУСКА")
    print("="*50)
    print(f"Всего обработано конфигов: {total_processed}")
    print(f"Всего ссылок из источников: {total_links}")
    print("\nПинги (не прошли):")
    print(f"  - таймаут/None: {ping_failures['timeout']}")
    print(f"  - слишком высокий (> max_p): {ping_failures['high']}")
    print(f"  - слишком низкий (< min_p): {ping_failures['low']}")
    print(f"  - отвал на full_ping_analysis: {ping_failures['full_fail']}")
    if ping_attempts_total > 0:
        success_rate = ping_attempts_success / ping_attempts_total * 100
        print(f"  Успешность full_ping: {success_rate:.1f}% ({ping_attempts_success}/{ping_attempts_total} попыток)")

    print("\nОтброшено по фильтрам:")
    for key, val in dropped_by.items():
        if val > 0:
            print(f"  - {key.replace('_', ' ').title()}: {val}")

    print(f"\nНесоответствие имени / ip-api: {country_mismatch}")
    print(f"Запросы к ip-api: {ipapi_requests} (неудачных: {ipapi_failed})")
    print(f"Пройденные этапы: {', '.join(stages_passed) or 'ни одного'}")
    print(f"--- 🏁 ГОТОВО за {time.perf_counter() - start_total:.1f}с ---")
    print("="*50)

if __name__ == "__main__":
    main()
