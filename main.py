# main.py
from collector.pcap_reader import read
from collector.live_capture import capture
from normalizer.flow_builder import flow_builder
from normalizer.extractor import extract_all
from engine.rule_loader import load_rules
from engine.rule_matcher import match
from output.reporter import report

import time
from datetime import datetime

RULES_PATH = "rules/recon_rules.yaml"
REPORT_INTERVAL = 5          # ← bạn có thể chỉnh 3, 5, 8, 10 tùy thích


def run_pcap(pcap_path: str) -> None:
    print(f"[*] Đọc file: {pcap_path}")

    builder = flow_builder()
    for pkt in read(pcap_path):
        builder.add_packet(pkt)

    flows = builder.get_flows()
    features_list = extract_all(flows)
    print(f"[*] Phát hiện {len(features_list)} flow")

    rules = load_rules(RULES_PATH)
    print(f"[*] Đã load {len(rules)} rule\n")

    all_alerts = []
    for features in features_list:
        alerts = match(features, rules)
        all_alerts.extend(alerts)

    report(all_alerts)


def run_live(interface: str | None = None) -> None:
    print(f"[*] Live capture — chạy liên tục (Ctrl+C để dừng)")
    print(f"[*] Alert sẽ hiển thị mỗi ~{REPORT_INTERVAL} giây khi phát hiện scan\n")

    rules = load_rules(RULES_PATH)
    print(f"[*] Đã load {len(rules)} rule\n")

    builder = flow_builder()
    last_report_time = time.time()

    try:
        for pkt in capture(interface=interface, packet_count=0):
            builder.add_packet(pkt)

            if time.time() - last_report_time >= REPORT_INTERVAL:
                flows = builder.get_flows()
                features_list = extract_all(flows)

                all_alerts = []
                for features in features_list:
                    alerts = match(features, rules)
                    all_alerts.extend(alerts)

                report(all_alerts)          # luôn in (có hay không cũng in)

                last_report_time = time.time()

    except KeyboardInterrupt:
        print("\n\n[!] Đã nhận Ctrl+C → Dừng live capture")
        print("\n[*] Kiểm tra lần cuối...")
        flows = builder.get_flows()
        features_list = extract_all(flows)
        all_alerts = []
        for features in features_list:
            alerts = match(features, rules)
            all_alerts.extend(alerts)
        report(all_alerts)
        print("\n[*] Live capture đã dừng.")


if __name__ == "__main__":
    MODE = "live"   # đổi thành "pcap" nếu muốn test file

    if MODE == "pcap":
        run_pcap("pcap/TCP_Syn.pcapng")
    else:
        run_live()