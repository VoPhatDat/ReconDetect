#engine/rule_matcher.py
from engine.alert import Alert

#Kiểm tra toán tử và giá trị điều kiện
def _check_conditions(value: float, op_val: dict) -> bool:  #value là giá thị thực tế, threshold (trong op_val) là giá trị ngưỡng
    for operator, threshold in op_val.items():              #op_val là danh sách các {operator: threshold} trong rule (xem rule là hiểu lol)

        if operator == 'gt' and not (value > threshold):
            return False
        elif operator == 'lt' and not (value < threshold):
            return False
        elif operator == 'gte' and not (value >= threshold):
            return False
        elif operator == 'lte' and not (value <= threshold):
            return False
        elif operator == 'eq' and not (value == threshold):
            return False
    return True

#Kiểm tra rule có match hay không
def _check_rule(features:dict, rule:dict) -> bool:
    for feature, op_val in rule["conditions"].items():
        value = features.get(feature, 0)
        if not _check_conditions(value, op_val):
            return False
    return True


"""
rules:
  - id: R200
    name: Massive Host Discovery
    confidence: CONFIRMED
    conditions:
      dst_ip_count: { gt: 100 }

  - id: R201
    name: Wide Network Scan (Fast)
    confidence: CONFIRMED
    conditions:
      dst_ip_count: { gt: 50 }
      duration:     { lt: 30 }
"""        
#Hàm so khớp các rule với features trả về một list Alert (in ra)
def match(features: dict, rules: list[dict]) -> list[Alert]:
    alerts = []
    for rule in rules:
        if _check_rule(features, rule):
            timestamp = features.get("timestamp", "")
            if not timestamp:
                # fallback: nếu không có timestamp trong features thì alert vẫn hoạt động
                timestamp = ""

            evidence = {f: features.get(f, 0) for f in rule["conditions"]}

            # Context giúp giải thích "bối cảnh scan" ngay trên console/txt.
            context_fields = [
                "packet_count",
                "port_count",
                "dst_ip_count",
                "duration",
                "tcp_port_count",
                "tcp_port_entropy",
                "udp_port_count",
                "udp_packet_count",
                "udp_port_entropy",
                "syn_count",
                "ack_count",
                "rst_count",
                "fin_count",
                "null_count",
                "xmas_count",
                "icmp_echo",
                "arp_request",
                "ack_ratio",
                "rst_ratio",
                "pkt_per_sec",
                "avg_interval",
                "port_entropy",
            ]
            context = {k: features.get(k, 0) for k in context_fields if k in features}

            alert = Alert(
                rule_id    = rule["id"],
                rule_name  = rule["name"],
                confidence = rule["confidence"],
                src_ip     = features["src_ip"],
                timestamp  = timestamp,
                conditions = rule["conditions"],
                evidence   = evidence,
                context    = context,
            )
            alerts.append(alert)
    return alerts