"""
Вспомогательный скрипт для workflow.
Использование:
  python3 extract_proxy.py count              → печатает количество конфигов
  python3 extract_proxy.py get <i>            → сохраняет i-й конфиг в proxy_current.json
"""
import json, sys, os

CONFIGS_FILE = "proxy_configs.json"

if not os.path.exists(CONFIGS_FILE):
    print("0")
    sys.exit(0)

with open(CONFIGS_FILE) as f:
    configs = json.load(f)

cmd = sys.argv[1] if len(sys.argv) > 1 else "count"

if cmd == "count":
    print(len(configs))

elif cmd == "get":
    i = int(sys.argv[2])
    if 0 <= i < len(configs):
        with open("proxy_current.json", "w") as f:
            json.dump(configs[i], f)
        print(f"OK: конфиг {i} сохранён")
    else:
        print(f"ERR: индекс {i} вне диапазона (0-{len(configs)-1})")
        sys.exit(1)
