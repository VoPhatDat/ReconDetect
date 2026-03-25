#normalizer/flow_builder.py

class flow_builder:
    def __init__(self):
        self.flows = {} #tạo dictionary để lưu trữ flow
    
    def _new_flow(self):
        return {
            'dst_ips': set(),
            'ports': set(),
            'port_list': [],
            'timestamps': [],
            'syn_count': 0,
            'ack_count': 0,
            'fin_count': 0,
            'rst_count': 0,
            'null_count': 0,
            'xmas_count': 0,
            'icmp_echo': 0,
            'arp_request': 0
        }
    
    #count flags chỉ cho TCP    
    def _count_flags(self, flow, flags):
        """
            FIN = 0x01 
            SYN = 0x02 
            RST = 0x04 
            PSH = 0x08 
            ACK = 0x10 
            URG = 0x20 
        """ 
        if flags == 0:
            flow['null_count'] += 1
        elif (flags & 0x29) == 0x29: # 0x29 = FIN + PSH + URG
            flow['xmas_count'] += 1
        else:
            if (flags & 0x02) and not (flags & 0x10): #SYN nhưng không có ACK 
                flow['syn_count'] += 1
            if (flags & 0x10) and not (flags & 0x02): #ACK nhưng không có SYN 
                flow['ack_count'] += 1
            if flags & 0x01:
                flow['fin_count'] += 1
            if flags & 0x04:
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
            flow['port_list'].append(pkt['dst_port'])
            self._count_flags(flow,pkt['flags'])
            
        elif pkt['protocol'] == 'UDP':
            flow['ports'].add(pkt['dst_port'])
            flow['port_list'].append(pkt['dst_port'])
            
        elif pkt['protocol'] == 'ICMP':
            if pkt.get('icmp_type') == 8:
                flow['icmp_echo'] += 1
                
        elif pkt['protocol'] == 'ARP':
            if pkt.get('arp_op') == 1:
                flow['arp_request'] += 1
                
    def get_flows(self):
        return self.flows
