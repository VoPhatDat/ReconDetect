import json
import subprocess
from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.json"


def load_config() -> dict:
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return json.load(f)


def get_tshark_path() -> str:
    try:
        cfg  = load_config()
        path = cfg.get("tshark_path", "")
        if path and Path(path).exists():
            return path
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    raise FileNotFoundError(
        "Không tìm thấy TShark.\n"
        "Kiểm tra lại tshark_path trong config/config.json"
    )


def list_interfaces() -> list[dict]:
    result = subprocess.run(
        [get_tshark_path(), "-D"],
        capture_output=True,
        text=True,
    )
    interfaces = []
    for line in result.stdout.strip().splitlines():
        parts = line.split(".", 1)
        if len(parts) == 2:
            interfaces.append({
                "index": parts[0].strip(),
                "name":  parts[1].strip(),
            })
    return interfaces


def print_interfaces():
    print("\nDanh sách interface:\n")
    for iface in list_interfaces():
        print(f"  [{iface['index']}] {iface['name']}")
    print()


if __name__ == "__main__":
    pass