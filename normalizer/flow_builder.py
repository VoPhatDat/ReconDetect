#normalizer/flow_builder.py


class flow_builder:
    def __init__(self, window_seconds: float | None = None):
        # window_seconds=None => tích lũy toàn bộ session (giống hành vi cũ, dùng cho pcap mode)
        self.window_seconds = window_seconds

        # flows: src_ip -> {"events": [packet_dict, ...]}
        self.flows: dict[str, dict] = {}

    def _new_flow_view(self) -> dict:
        # Flow view dùng để extractor tính feature
        return {
            "dst_ips": set(),
            "ports": set(),
            "port_list": [],
            "timestamps": [],
            # Protocol-specific (giúp rule TCP scan không bị ảnh hưởng bởi UDP)
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
    def _count_flags(self, flow_view: dict, flags: int | None) -> None:
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
            flow_view["null_count"] += 1
        # XMAS scan "chuẩn" thường là đúng FIN+PSH+URG, không kèm ACK/SYN/RST.
        elif flags == 0x29:
            flow_view["xmas_count"] += 1
        else:
            if (flags & 0x02) and not (flags & 0x10):  # SYN nhưng không có ACK
                flow_view["syn_count"] += 1
            if (flags & 0x10) and not (flags & 0x02):  # ACK nhưng không có SYN
                flow_view["ack_count"] += 1
            # FIN scan nên đếm FIN-only để tránh false positive từ FIN+ACK đóng kết nối bình thường.
            if flags == 0x01:
                flow_view["fin_count"] += 1
            if flags & 0x04:
                flow_view["rst_count"] += 1

    def _purge_old(self, flow_state: dict, now_ts: float) -> None:
        if self.window_seconds is None:
            return

        cutoff = now_ts - self.window_seconds
        events = flow_state["events"]
        # events purge theo timestamp từng packet
        flow_state["events"] = [e for e in events if float(e.get("timestamp", 0)) >= cutoff]

    def add_packet(self, pkt: dict) -> None:
        src_ip = pkt["src_ip"]
        now_ts = float(pkt["timestamp"])

        if src_ip not in self.flows:
            self.flows[src_ip] = {"events": []}

        flow_state = self.flows[src_ip]
        flow_state["events"].append(pkt)
        self._purge_old(flow_state, now_ts)

    def _build_flow_view_from_events(self, events: list[dict]) -> dict:
        flow_view = self._new_flow_view()
        for pkt in events:
            flow_view["packet_count"] += 1
            flow_view["dst_ips"].add(pkt["dst_ip"])
            flow_view["timestamps"].append(pkt["timestamp"])

            proto = pkt["protocol"]
            if proto == "TCP":
                flow_view["ports"].add(pkt["dst_port"])
                flow_view["port_list"].append(pkt["dst_port"])
                flow_view["tcp_ports"].add(pkt["dst_port"])
                flow_view["tcp_port_list"].append(pkt["dst_port"])
                flow_view["tcp_timestamps"].append(pkt["timestamp"])
                self._count_flags(flow_view, pkt.get("flags"))
            elif proto == "UDP":
                flow_view["ports"].add(pkt["dst_port"])
                flow_view["port_list"].append(pkt["dst_port"])
                flow_view["udp_ports"].add(pkt["dst_port"])
                flow_view["udp_port_list"].append(pkt["dst_port"])
                flow_view["udp_timestamps"].append(pkt["timestamp"])
            elif proto == "ICMP":
                if pkt.get("icmp_type") == 8:
                    flow_view["icmp_echo"] += 1
            elif proto == "ARP":
                if pkt.get("arp_op") == 1:
                    flow_view["arp_request"] += 1

        return flow_view

    def get_flows(self, now_ts: float | None = None):
        """
        Trả flow dict (đúng shape để extractor.py sử dụng).
        """
        flows_view = {}
        for src_ip, flow_state in self.flows.items():
            # Khi window_seconds bật và có khoảng thời gian giữa các lần gọi,
            # cần purge thêm trước khi build flow view.
            if now_ts is not None and self.window_seconds is not None:
                self._purge_old(flow_state, now_ts)

            events = flow_state["events"]
            if not events:
                continue

            flows_view[src_ip] = self._build_flow_view_from_events(events)

        return flows_view
