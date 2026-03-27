#normalizer/extractor.py
import math
from collections import Counter
from datetime import datetime

# Các feature mà extractor có thể xuất ra (dùng để validate rule).
SUPPORTED_FEATURES = {
    "src_ip",
    "port_count",
    "dst_ip_count",
    "duration",
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
    "tcp_port_count",
    "tcp_port_entropy",
    "udp_port_count",
    "udp_packet_count",
    "udp_port_entropy",
    "packet_count",
    # Metadata dùng cho hiển thị
    "timestamp",
}

#Tính toán entropy từ ports_list   
def _entropy(data):
    if len(data) < 2:
        return 0.0
    counter = Counter(data) #tính số lần xuất hiện của mỗi port trong port_list
    total = len(data)
    return round(
        -sum((c / total) * math.log2(c / total) for c in counter.values()), #công thức entropy,  khó hiểu vcl:))
        4
    )  
    
#Nhận một flow của một ip -> tính feature -> trả dict
def extract(src_ip: str, flow: dict) -> dict:
    ports = flow['ports']
    dst_ips = flow['dst_ips']
    timestamps = flow['timestamps']
    syn_count = flow['syn_count']
    ack_count = flow['ack_count']
    rst_count = flow['rst_count']
    
    # Tính toán các feature cơ bản
    port_count = len(ports)
    dst_ip_count = len(dst_ips)
    # dpkt (hoặc một số pipeline) có thể trả timestamp dạng Decimal.
    # datetime.fromtimestamp() chỉ nhận int/float => ép về float để tránh TypeError.
    ts_list = [float(t) for t in timestamps] if timestamps else []
    first_ts = min(ts_list) if ts_list else 0.0
    last_ts = max(ts_list) if ts_list else 0.0
    duration = last_ts - first_ts if len(ts_list) >= 2 else 0.0
    
    #Tính toán tỷ lệ SYN/ACK và SYN/RST
    ack_ratio = ack_count / syn_count if syn_count > 0 else 0.0
    rst_ratio = rst_count / syn_count if syn_count > 0 else 0.0
    
    # Tính toán gói tin tốc độ gửi gói và thời gian trung bình giữa các gói
    pkt_per_sec = len(ts_list) / duration if duration > 0 else 0.0
    # avg_interval ~ thời gian trung bình giữa các packet (n-1 khoảng)
    avg_interval = duration / (len(ts_list) - 1) if len(ts_list) > 1 else 0.0
 

    port_entropy = _entropy(flow['port_list'])

    # TCP-only metrics (giúp giảm false positive cho các rule TCP scan)
    tcp_ports = flow.get("tcp_ports", set())
    tcp_port_list = flow.get("tcp_port_list", [])
    udp_ports = flow.get("udp_ports", set())
    udp_port_list = flow.get("udp_port_list", [])
    udp_ts_list = [float(t) for t in flow.get("udp_timestamps", [])]

    tcp_port_count = len(tcp_ports)
    tcp_port_entropy = _entropy(tcp_port_list)
    udp_port_count = len(udp_ports)
    udp_packet_count = len(udp_ts_list)
    udp_port_entropy = _entropy(udp_port_list)
    packet_count = flow.get("packet_count", len(ts_list))

    # trả về feature dict cho Rule Engine
    return {
        'src_ip':       src_ip,
        # Lấy thời điểm cuối cùng trong flow để alert "gắn" đúng thời gian traffic
        'timestamp':   datetime.fromtimestamp(float(last_ts)).strftime("%Y-%m-%d %H:%M:%S")
                       if ts_list else "",
        'port_count':   port_count,
        'dst_ip_count': dst_ip_count,
        'duration':     round(duration, 4),
        'syn_count':    syn_count,
        'ack_count':    ack_count,
        'rst_count':    rst_count,
        'fin_count':    flow['fin_count'],
        'null_count':   flow['null_count'],
        'xmas_count':   flow['xmas_count'],
        'icmp_echo':    flow['icmp_echo'],
        'arp_request': flow.get('arp_request', 0),
        'ack_ratio':    round(ack_ratio, 4),
        'rst_ratio':    round(rst_ratio, 4),
        'pkt_per_sec':  round(pkt_per_sec, 4),
        'avg_interval': round(avg_interval, 4),
        'port_entropy': port_entropy,
        # TCP/UDP-only metrics (tránh phụ thuộc vào traffic trộn)
        'tcp_port_count': tcp_port_count,
        'tcp_port_entropy': tcp_port_entropy,
        'udp_port_count': udp_port_count,
        'udp_packet_count': udp_packet_count,
        'udp_port_entropy': udp_port_entropy,
        'packet_count': packet_count,
    }
   
#extract thông tin khi đã tính toán các feature cho tất cả các flow -> trả về list dict để đưa vào Rule Engine    
def extract_all(flows: dict) -> list[dict]:
    return [
        extract(src_ip, data)
        for src_ip, data in flows.items()
        if len(data['timestamps']) >= 2
    ]
    
    
    