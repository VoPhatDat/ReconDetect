#normalizer/extractor.py
import math
from collections import Counter

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
    
    #Tính toán các feature cơ bản
    port_count = len(ports)
    dst_ip_count = len(dst_ips)
    duration = max(timestamps) - min(timestamps) if len(timestamps) >= 2 else 0.0
    
    #Tính toán tỷ lệ SYN/ACK và SYN/RST
    ack_ratio = ack_count / syn_count if syn_count > 0 else 0.0
    rst_ratio = rst_count / syn_count if syn_count > 0 else 0.0
    
    #tính toán gói tin tốc độ gửi gói và thời gian trung bình giữa các gói
    pkt_per_sec = syn_count / duration if duration > 0 else 0.0
    avg_interval = duration / len(timestamps) if len(timestamps) > 1 else 0.0
 

    port_entropy = _entropy(flow['port_list'])  

    # trả về feature dict cho Rule Engine
    return {
        'src_ip':       src_ip,
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
        'ack_ratio':    round(ack_ratio, 4),
        'rst_ratio':    round(rst_ratio, 4),
        'pkt_per_sec':  round(pkt_per_sec, 4),
        'avg_interval': round(avg_interval, 4),
        'port_entropy': port_entropy,
    }
   
#extract thông tin khi đã tính toán các feature cho tất cả các flow -> trả về list dict để đưa vào Rule Engine    
def extract_all(flows: dict) -> list[dict]:
    return [
        extract(src_ip, data)
        for src_ip, data in flows.items()
        if len(data['timestamps']) >= 2
    ]
    
#testing
def test():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    from collector.pcap_reader import read
    from normalizer.flow_builder import flow_builder

    fb = flow_builder()
    for pkt in read("../_demo/pcap/TCP_Syn.pcapng"):
        fb.add_packet(pkt)

    features = extract_all(fb.get_flows())
    for f in features:
        print(f"\n{'─'*50}")
        print(f"  IP:           {f['src_ip']}")
        print(f"  port_count:   {f['port_count']}")
        print(f"  dst_ip_count: {f['dst_ip_count']}")
        print(f"  duration:     {f['duration']}s")
        print(f"  syn_count:    {f['syn_count']}")
        print(f"  ack_count:    {f['ack_count']}")
        print(f"  rst_count:    {f['rst_count']}")
        print(f"  ack_ratio:    {f['ack_ratio']}")
        print(f"  rst_ratio:    {f['rst_ratio']}")
        print(f"  pkt_per_sec:  {f['pkt_per_sec']}")
        print(f"  avg_interval: {f['avg_interval']}s")
        print(f"  port_entropy: {f['port_entropy']}")

if __name__ == "__main__":
    test()    
    
    