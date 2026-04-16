# main.py
from __future__ import annotations

import argparse
import glob
import time

from collector import parser
from collector.live_capture import capture
from collector.pcap_reader import read
from engine.rule_loader import load_rules
from engine.rule_matcher import match
from normalizer.extractor import extract_all
from normalizer.flow_aggregator import FlowAggregateBuilder
from output.reporter import report


# Có thể là 1 file YAML hoặc cả thư mục chứa nhiều file YAML.
RULES_PATH = "rules"


def run_pcap(pcap_path: str, output_txt_path: str | None = None) -> None:
    # Nếu chứa wildcard, expand thành list files
    if '*' in pcap_path:
        pcap_files = glob.glob(pcap_path)
        if not pcap_files:
            print(f"[!] No files found matching: {pcap_path}")
            return
        print(f"[*] Found {len(pcap_files)} PCAP files matching: {pcap_path}")
        for file in pcap_files:
            process_single_pcap(file, output_txt_path)
        return

    # Single file
    process_single_pcap(pcap_path, output_txt_path)


def process_single_pcap(pcap_path: str, output_txt_path: str | None = None) -> None:
    print("\n")
    print(f"--- Processing: {pcap_path} ---")
    print(f"[*] Reading file: {pcap_path}")

    builder = FlowAggregateBuilder(window_seconds=None)  # pcap mode: tích lũy toàn session
    for pkt in read(pcap_path):
        builder.add_packet(pkt)

    flows = builder.get_flows()
    features_list = extract_all(flows)
    print(f"[*] Detected {len(features_list)} flows")

    rules = load_rules(RULES_PATH)
    print(f"[*] Loaded {len(rules)} rules\n")

    all_alerts = []
    for features in features_list:
        alerts = match(features, rules)
        all_alerts.extend(alerts)

    # Print file header for alerts
    if all_alerts:
        print(f"=== Alerts from {pcap_path} ===")
    
    report(
        all_alerts,
        output_txt_path=output_txt_path,
        quiet_if_empty=False,  # In "No alerts detected" nếu empty
        one_line_console=True,  # Mỗi alert 1 dòng như live mode
        reset_table_header=True,  # Reset header cho mỗi file
    )
    
    print()  # Empty line after file processing


def run_live(
    interface: str | None = None,
    report_interval: float = 1.0,
    window_seconds: float = 10.0,
    output_txt_path: str | None = None,
    rearm_seconds: float = 15.0,
) -> None:
    print(f"[*] Live capture (Ctrl+C to stop)")
    print(f"[*] report_interval={report_interval}s, window_seconds={window_seconds}s")
    print(f"[*] Rearm alert per (src_ip, rule_id): {rearm_seconds}s\n")

    rules = load_rules(RULES_PATH)
    print(f"[*] Loaded {len(rules)} rules\n")

    builder = FlowAggregateBuilder(window_seconds=window_seconds)
    # key=(src_ip, rule_id) -> last_alert_ts_epoch
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
        print("\n\n[!] KeyboardInterrupt received. Finalizing alerts before exit...")
        print("[*] Processing final alerts...")

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
        print("\n[*] Live capture has stopped. Exiting.")



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
def _parse_args():
    parser = argparse.ArgumentParser(
        description="ReconDetect - Rule-based network reconnaissance detection system",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Analyze PCAP file
  python main.py --mode pcap --pcap-path "pcap/scan.pcapng"
 
  # Analyze all PCAP files in a directory
  python main.py --mode pcap --pcap-path "pcap/*.pcapng"
 
  # Monitor live traffic on eth0
  sudo python main.py --mode live --interface eth0
 
  # Live capture with 30s window, save alerts to file
  sudo python main.py --mode live --window-seconds 30 --output-txt alerts.txt
 
  # Custom report interval (faster alerts)
  sudo python main.py --mode live --report-interval 0.5
 
DOCUMENTATION:
  See README.md for overview
  See rule_schema.md for rule format and features
        """
    )
    parser.add_argument("--list-interfaces",action="store_true",help="List available network interfaces and exit")
    parser.add_argument("--mode",choices=["live", "pcap"],default="live",help="Detection mode: 'live' (monitor interface) or 'pcap' (analyze file) (default: live)")
    parser.add_argument("--pcap-path",default="pcap/Nmap-and-Wireshark-Lab-main/SX Scan.pcapng",help="Path to PCAP file or pattern (e.g., 'pcap/*.pcapng') to analyze all matching files (required for --mode pcap)")
    parser.add_argument("--interface",default=None,help="Network interface to capture from (default: read from config.json)")
    parser.add_argument("--window-seconds",type=float,default=10.0,help="Rolling window size for flow analysis in seconds (default: 10.0)")
    parser.add_argument("--report-interval",type=float,default=1.0,help="Interval between alert reports in seconds (default: 1.0)")
    parser.add_argument("--output-txt",default=None,help="Log file path for alerts (append mode). Omit to log only to console")
    parser.add_argument("-l", "--log-file",default=None,help="Alias for --output-txt (for convenience)")
    parser.add_argument("--rearm-seconds",type=float,default=15.0,help="Minimum time (seconds) before same (src_ip, rule_id) can alert again (default: 15.0)")
    return parser.parse_args()
 

if __name__ == "__main__":
    args = _parse_args()
    
    if args.list_interfaces:  # ← Lưu ý: dấu gạch ngang (_) trong flag name
        from collector.platform import print_interfaces
        print_interfaces()
        import sys
        sys.exit(0)
    
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