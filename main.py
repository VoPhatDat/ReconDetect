# main.py
from collector.pcap_reader import read
from collector.live_capture import capture
from normalizer.flow_builder import flow_builder
from normalizer.extractor import extract_all
from engine.rule_loader import load_rules
from engine.rule_matcher import match
from output.reporter import report

RULES_PATH = "rules/recon_rules.yaml"

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


def run_live(interface: str = None, packet_count: int = 500) -> None:
    print(f"[*] Live capture — {packet_count} packets...")

    rules = load_rules(RULES_PATH)
    print(f"[*] Đã load {len(rules)} rule\n")

    builder = flow_builder()
    for pkt in capture(interface=interface, packet_count=packet_count):
        builder.add_packet(pkt)

    flows = builder.get_flows()
    features_list = extract_all(flows)
    print(f"[*] Phát hiện {len(features_list)} flow\n")

    all_alerts = []
    for features in features_list:
        alerts = match(features, rules)
        all_alerts.extend(alerts)

    report(all_alerts)


if __name__ == "__main__":
    # chọn mode
    MODE = "live"   # "pcap" hoặc "live"

    if MODE == "pcap":
        run_pcap("pcap/TCP_Syn.pcapng")
    else:
        run_live(packet_count=1000)