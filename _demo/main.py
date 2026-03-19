from scapy.all import rdpcap, IP, TCP
def readPCAP(s):
	packets = rdpcap(f"pcap/{s}")
	return packets

def scanPCAP (packets):
	scan = {}
	for pkt in packets:
	    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)): #Nếu không có gói IP & TCP thì bỏ qua
	        continue

	    src   = pkt[IP].src
	    dst   = pkt[IP].dst
	    flags = pkt[TCP].flags
	    dport = pkt[TCP].dport
	    ts    = float(pkt.time)

	    #Nếu là flags SYN
	    if flags == "S":
	        if src not in scan: #nếu IP chưa được ghi nhận vào trong scan thì tập mới
	            scan[src] = {
	                "ports":  set(),
	                "times":  [],
	                "syn":    0,
	                "ack":    0,
	            }
	        #thêm thông tin vào trong IP 
	        scan[src]["ports"].add(dport)
	        scan[src]["times"].append(ts)
	        scan[src]["syn"] += 1

	    #Nếu flags là ACK (hoàn thành handshake) thì ghi nhận
	    elif flags == "A":
	        if src in scan: #Nếu IP đã được ghi nhận vì phải SYN trước mới có ACK, nếu không ghi nhận thì bỏ qua
	            scan[src]["ack"] += 1
	return scan


def Analysis(scan):
	# Giao diện
	print(f"{'IP':<18} {'Ports':>6} {'SYN':>5} {'ACK':>5} {'Duration':>10}  Status")
	print("-" * 65)

	for ip, data in scan.items():
	    ports    = data["ports"]
	    times    = data["times"]
	    syn      = data["syn"]
	    ack      = data["ack"]

		#Nếu trong tập timers chỉ có một phần tử thì bỏ qua (có 2 gói mới tính được duration)
	    if len(times) < 2: 
	        continue

	    duration       = max(times) - min(times)
	    incomplete     = ack < syn * 0.3  
	    many_ports     = len(ports) > 20
	    fast           = duration < 5# giây

	    if many_ports and fast and incomplete:
	        status = "🔴 SYN SCAN"
	    elif many_ports and incomplete:
	        status = "🟡 SLOW SCAN"  # slow-and-low
	    else:
	        status = "✅ normal"

	    print(f"{ip:<18} {len(ports):>6} {syn:>5} {ack:>5} {duration:>9.2f}s  {status}")

if __name__ == "__main__":
	s = "TCP_Syn.pcapng"
	d = readPCAP(s)
	scanninglist = scanPCAP(d)
	Analysis(scanninglist)