#normalizer/flow_builder.py



class flow_builder:
    def __init__(self):
        self.flows = {} #tạo dictionary để lưu trữ flow
    
    def _new_flow(self):
        return {
            'dst_ips': set(),
            'ports': set(),
            'timestamps': [],
            'syn_count': 0,
            'ack_count': 0,
            'fin_count': 0,
            'rst_count': 0,
            'null_count': 0,
            'xmas_count': 0,
            'icmp_echo': 0
        }
        
    def _count_flags(self, flow, flags):
        """
            FIN = 0x01 
            SYN = 0x02 
            RST = 0x04 
            PSH = 0x08 
            ACK = 0x10 
            URG = 0x20 
        """ 
        if flags == 0: #không có flag
            flow['null_count'] += 1 
        elif (flags & 0x29) == 0x29: # URG, PSH, FIN
            flow['xmas_count'] += 1
        elif (flags & 0x02) and not (flags & 0x10):#SYN nhưng không có ACK -> SYN thuần
            flow['syn_count'] += 1
        elif (flags & 0x10) and not (flags & 0x02): # ACK nhưng không có SYN -> hoàn thành handshake
            flow['ack_count'] += 1
        elif flags & 0x01: #FIN
            flow['fin_count'] += 1
        elif flags & 0x04: #RST
            flow['rst_count'] += 1
            
    def  add_packet(self, pkt):
        src_ip = pkt['src_ip']
        
        #Nếu chưa có src_ip
        if src_ip not in self.flows:
            self.flows[src_ip] = self._new_flow()
        
        flow = self.flows[src_ip]
        
        #thông tin chung
        flow['dst_ips'].add(pkt['dst_ip'])
        flow['timestamps'].append(pkt['timestamp'])
        
        if pkt['protocol'] == 'TCP':
            flow['ports'].add(pkt['dst_port'])
            self._count_flags(flow,pkt['flags'])
        elif pkt['protocol'] == 'UDP':
            flow['ports'].add(pkt['dst_port'])
        elif pkt['protocol'] == 'ICMP':
            if pkt.get('icmp_type') == 8:
                flow['icmp_echo'] += 1
                
    def get_flows(self):
        return self.flows

def run_test():
    import sys
    sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent.parent))
    
    from collector.live_capture import capture
    from collector.parser import parse_packet  # thêm dòng này

    fb = flow_builder()

    print("Đang bắt gói tin... (Ctrl+C để dừng)\n")

    try:
        for pkt in capture(packet_count=50):  # bắt 50 gói
            fb.add_packet(pkt)
            print(f"  + {pkt['protocol']} {pkt['src_ip']} → {pkt['dst_ip']}:{pkt.get('dst_port', '-')}")

    except KeyboardInterrupt:
        pass

    print("\n─── Kết quả flows ───\n")
    for ip, flow in fb.get_flows().items():
        if len(flow['timestamps']) < 2:
            continue
        print(f"IP: {ip}")
        print(f"  ports:     {flow['ports']}")
        print(f"  syn_count: {flow['syn_count']}")
        print(f"  ack_count: {flow['ack_count']}")
        print(f"  duration:  {max(flow['timestamps']) - min(flow['timestamps']):.2f}s")
        print()
if __name__ == '__main__':
    run_test()