# output/reporter.py
from engine.alert import Alert
from datetime import datetime

def print_alert(alert: Alert) -> None:
    ts = alert.timestamp[-8:]   # chỉ lấy HH:MM:SS
    conf = alert.confidence[:4] # CONF → C, SUSPECTED → S
    
    # 1 dòng duy nhất, rất gọn
    print(f"[{ts}] {conf} | {alert.rule_id} | {alert.src_ip} | {alert.rule_name}")


def report(alerts: list[Alert]) -> None:
    if not alerts:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ Không phát hiện scan mới")
        return

    # Sắp xếp theo thời gian (mới nhất ở dưới)
    alerts.sort(key=lambda a: a.timestamp)

    print(f"\n🔥 Phát hiện {len(alerts)} alert:\n")
    for alert in alerts:
        print_alert(alert)
    print("-" * 90)   # đường phân cách