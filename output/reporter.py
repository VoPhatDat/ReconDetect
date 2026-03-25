# output/reporter.py
from engine.alert import Alert
from datetime import datetime

def print_alert(alert: Alert) -> None:
    # Format ngắn gọn, đẹp, chỉ 2 dòng
    ts = alert.timestamp[-8:]  # chỉ lấy giờ:phút:giây
    
    line1 = f"[{ts}] [{alert.confidence}] {alert.rule_id} — {alert.rule_name}"
    line2 = f"    → {alert.src_ip}   evidence: " + \
            ", ".join(f"{k}={v}" for k, v in alert.evidence.items())
    
    print(line1, end=" ")
    print(line2)
    print()  # cách dòng cho dễ nhìn


def report(alerts: list[Alert]) -> None:
    if not alerts:
        print(f"  [✓] Không phát hiện scan mới ({datetime.now().strftime('%H:%M:%S')})")
        return

    # Sắp xếp theo thời gian (mới nhất ở dưới)
    alerts.sort(key=lambda a: a.timestamp)

    print(f"\n  🔥 Phát hiện {len(alerts)} alert:\n")
    for alert in alerts:
        print_alert(alert)