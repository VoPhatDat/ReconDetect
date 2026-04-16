#normalizer/flow_aggregator.py


class FlowAggregateBuilder:
    def __init__(self, window_seconds: float | None = None):
        # window_seconds=None => tích lũy toàn bộ session (giống hành vi cũ, dùng cho pcap mode)
        self.window_seconds = window_seconds

        #tương tự như self.flows = {} nhưng quy định  rõ str là key còn dict là value (giúp type hint rõ ràng hơn)
        # này là tập hợp nhiều các flow state nha
        self.flows: dict[str, dict] = {}

    def _new_flow_aggregate(self) -> dict:
        # Flow view dùng để extractor tính feature
        return {
            "dst_ips": set(),
            "ports": set(),
            "port_list": [],
            "timestamps": [],
            "tcp_ports": set(),
            "tcp_port_list": [],
            "tcp_timestamps": [],
            "udp_ports": set(),
            "udp_port_list": [],
            "udp_timestamps": [],
            "packet_count": 0,
            "syn_count": 0,
            "ack_count": 0,
            "fin_count": 0,
            "rst_count": 0,
            "null_count": 0,
            "xmas_count": 0,
            "icmp_echo": 0,
            "arp_request": 0,
        }

    # count flags chỉ cho TCP
    def _count_flags(self, flow_aggregate: dict, flags: int | None) -> None:
        """
        FIN = 0x01
        SYN = 0x02
        RST = 0x04
        PSH = 0x08
        ACK = 0x10
        URG = 0x20
        """
        if flags is None:
            return

        if flags == 0:
            flow_aggregate["null_count"] += 1
        # XMAS scan "chuẩn" thường là đúng FIN+PSH+URG, không kèm ACK/SYN/RST.
        elif flags == 0x29:
            flow_aggregate["xmas_count"] += 1
        else:
            if (flags & 0x02) and not (flags & 0x10):  # SYN nhưng không có ACK
                flow_aggregate["syn_count"] += 1
            if (flags & 0x10) and not (flags & 0x02):  # ACK nhưng không có SYN
                flow_aggregate["ack_count"] += 1
            # FIN scan nên đếm FIN-only để tránh false positive từ FIN+ACK đóng kết nối bình thường.
            if flags == 0x01:
                flow_aggregate["fin_count"] += 1
            if flags & 0x04:
                flow_aggregate["rst_count"] += 1

    def _purge_old(self, flow_state: dict, now_ts: float) -> None:
        # nếu không set window_seconds thì giữ nguyên toàn bộ flow state
        if self.window_seconds is None:
            return

        #nếu có thì nó sẽ tính thì cutoff, ví dụ window_second là 10s thì nó chỉ lấy gói tin từ đoạn thời gian 10s gần nhất, còn lại sẽ bị loại bỏ khỏi flow state
        cutoff = now_ts - self.window_seconds
        events = flow_state["events"]
        flow_state["events"] = [e for e in events if float(e.get("timestamp", 0)) >= cutoff]

    def add_packet(self, pkt: dict) -> None:
        # lấy src_ip và timestamp để quản lý flow và purge theo window_seconds nếu cần
        src_ip = pkt["src_ip"]
        now_ts = float(pkt["timestamp"])

        # nếu src_ip chưa có trong flows thì khởi tạo flow state mới, sau đó append packet vào events của flow state đó
        if src_ip not in self.flows:
            self.flows[src_ip] = {"events": []}

        # nếu chưa thì tạo flow state mới với key là src_ip và value là dict có key "events" chứa list packet, sau đó append packet vào list events của flow state đó
        # flow_state trỏ đến flows của src_ip hiện tại, sau đó append packet vào list events của flow state đó
        # về cơ bản nó giống với self.flows[src_ip]["events"].append(pkt) nhưng có thêm bước gán biến flow_state để code dễ đọc hơn
        flow_state = self.flows[src_ip]
        flow_state["events"].append(pkt)
        
        #lấy packet mới tránh flow tích lũy quá lâu 
        self._purge_old(flow_state, now_ts)

    def _build_flow_aggregate_from_events(self, events: list[dict]) -> dict:
        flow_aggregate = self._new_flow_aggregate()
        for pkt in events:
            flow_aggregate["packet_count"] += 1
            flow_aggregate["dst_ips"].add(pkt["dst_ip"])
            flow_aggregate["timestamps"].append(pkt["timestamp"])

            proto = pkt["protocol"]
            if proto == "TCP":
                flow_aggregate["ports"].add(pkt["dst_port"])
                flow_aggregate["port_list"].append(pkt["dst_port"])
                flow_aggregate["tcp_ports"].add(pkt["dst_port"])
                flow_aggregate["tcp_port_list"].append(pkt["dst_port"])
                flow_aggregate["tcp_timestamps"].append(pkt["timestamp"])
                self._count_flags(flow_aggregate, pkt.get("flags"))
            elif proto == "UDP":
                flow_aggregate["ports"].add(pkt["dst_port"])
                flow_aggregate["port_list"].append(pkt["dst_port"])
                flow_aggregate["udp_ports"].add(pkt["dst_port"])
                flow_aggregate["udp_port_list"].append(pkt["dst_port"])
                flow_aggregate["udp_timestamps"].append(pkt["timestamp"])
            elif proto == "ICMP":
                if pkt.get("icmp_type") == 8:
                    flow_aggregate["icmp_echo"] += 1
            elif proto == "ARP":
                if pkt.get("arp_op") == 1:
                    flow_aggregate["arp_request"] += 1

        return flow_aggregate

    def get_flows(self, now_ts: float | None = None):
        # flow aggregate 
        flows_view: dict[str, dict] = {}
        
        for src_ip, flow_state in self.flows.items():
            # Khi window_seconds bật và có khoảng thời gian giữa các lần gọi,
            # cần purge thêm trước khi build flow view.
            if now_ts is not None and self.window_seconds is not None:
                self._purge_old(flow_state, now_ts)

            events = flow_state["events"]
            if not events:
                continue

            flows_view[src_ip] = self._build_flow_aggregate_from_events(events)

        return flows_view

