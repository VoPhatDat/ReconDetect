# main.py
from __future__ import annotations

import argparse
import time

from collector.live_capture import capture
from collector.pcap_reader import read
from engine.rule_loader import load_rules
from engine.rule_matcher import match
from normalizer.extractor import extract_all
from normalizer.flow_builder import flow_builder
from output.reporter import report


# Có thể là 1 file YAML hoặc cả thư mục chứa nhiều file YAML.
RULES_PATH = "rules"


def run_pcap(pcap_path: str, output_txt_path: str | None = None) -> None:
    print(f"[*] Đọc file: {pcap_path}")

    builder = flow_builder(window_seconds=None)  # pcap mode: tích lũy toàn session
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

    report(
        all_alerts,
        output_txt_path=output_txt_path,
        quiet_if_empty=False,
        one_line_console=False,
    )


def run_live(
    interface: str | None = None,
    report_interval: float = 1.0,
    window_seconds: float = 10.0,
    output_txt_path: str | None = None,
    rearm_seconds: float = 15.0,
) -> None:
    print(f"[*] Live capture — chạy liên tục (Ctrl+C để dừng)")
    print(f"[*] report_interval={report_interval}s, window_seconds={window_seconds}s")
    print(f"[*] Rearm alert theo timestamp: {rearm_seconds}s cho mỗi (src_ip, rule_id)\n")

    rules = load_rules(RULES_PATH)
    print(f"[*] Đã load {len(rules)} rule\n")

    builder = flow_builder(window_seconds=window_seconds)
    # key=(src_ip, rule_id) -> last_alert_ts_epoch
    # Không chặn vĩnh viễn như bản cũ; chỉ chống spam trong cửa sổ ngắn.
    last_alert_by_key: dict[tuple[str, str], float] = {}

    last_report_time = time.time()
    try:
        for pkt in capture(interface=interface, packet_count=0):
            builder.add_packet(pkt)

            if time.time() - last_report_time < report_interval:
                continue

            # Purge + build flows trong cửa sổ thời gian gần nhất
            # Purge theo timestamp của packet (được builder thực hiện tại add_packet)
            # tránh mismatch giữa time.time() (epoch) và timestamp của dpkt/TShark (có thể tương đối).
            flows = builder.get_flows()
            features_list = extract_all(flows)

            # In alert ngay khi detect (trong phạm vi mỗi chu kỳ report_interval)
            for features in features_list:
                for alert in match(features, rules):
                    key = (alert.src_ip, alert.rule_id)
                    try:
                        alert_ts = time.mktime(time.strptime(alert.timestamp, "%Y-%m-%d %H:%M:%S"))
                    except (ValueError, TypeError):
                        # fallback nếu timestamp thiếu/format khác
                        alert_ts = time.time()

                    last_ts = last_alert_by_key.get(key)
                    # Chỉ alert lại khi đã qua khoảng rearm_seconds, để:
                    # 1) Không spam trong 1 đợt scan dài
                    # 2) Vẫn alert lại khi attacker scan lần tiếp theo
                    if last_ts is not None and (alert_ts - last_ts) < rearm_seconds:
                        continue

                    last_alert_by_key[key] = alert_ts
                    report(
                        [alert],
                        output_txt_path=output_txt_path,
                        quiet_if_empty=True,
                        one_line_console=True,
                    )

            last_report_time = time.time()

    except KeyboardInterrupt:
        print("\n\n[!] Đã nhận Ctrl+C → Dừng live capture")
        print("[*] Kiểm tra lần cuối trong cửa sổ hiện tại...")

        flows = builder.get_flows()
        features_list = extract_all(flows)
        final_alerts = []
        for features in features_list:
            final_alerts.extend(match(features, rules))

        report(
            final_alerts,
            output_txt_path=output_txt_path,
            quiet_if_empty=False,
            one_line_console=False,
        )
        print("\n[*] Live capture đã dừng.")


def _parse_args():
    parser = argparse.ArgumentParser(description="ReconDetect - active scanning detection (Stage 1 rules)")
    parser.add_argument("--mode", choices=["live", "pcap"], default="live")
    parser.add_argument("--pcap-path", default="pcap/Nmap-and-Wireshark-Lab-main/SX Scan.pcapng")
    parser.add_argument("--interface", default=None, help="Tùy chọn interface cho live capture (mặc định đọc từ config)")
    parser.add_argument("--report-interval", type=float, default=1.0)
    parser.add_argument("--window-seconds", type=float, default=10.0)
    parser.add_argument("--output-txt", default=None, help="Ghi alert ra file txt (append)")
    parser.add_argument("-l", "--log-file", default=None, help="Alias ghi log txt (append)")
    parser.add_argument(
        "--rearm-seconds",
        type=float,
        default=15.0,
        help="Số giây tối thiểu trước khi cùng (src_ip, rule_id) được alert lại",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    output_txt = args.log_file or args.output_txt
    if args.mode == "pcap":
        run_pcap(args.pcap_path, output_txt_path=output_txt)
    else:
        run_live(
            interface=args.interface,
            report_interval=args.report_interval,
            window_seconds=args.window_seconds,
            output_txt_path=output_txt,
            rearm_seconds=args.rearm_seconds,
        )