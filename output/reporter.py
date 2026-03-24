#output/reporter.py
from engine.alert import Alert

def print_alert(alert: Alert) -> None:
    border = "═" * 50
    print(border)
    print(f"  [{alert.confidence}] {alert.rule_id} — {alert.rule_name}")
    print(f"  src_ip    : {alert.src_ip}")
    print(f"  timestamp : {alert.timestamp}")
    print(f"  evidence  :")
    for field, value in alert.evidence.items():
        print(f"    {field:<15}: {value}")
    print(border)
    print()
    
def report(alerts: list[Alert]) -> None:
    if not alerts:
        print("  [✓] Không phát hiện tấn công nào.")
        return

    print(f"\n  Phát hiện {len(alerts)} alert:\n")
    for alert in alerts:
        print_alert(alert)