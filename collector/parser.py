# collector/parser.py
import socket
import dpkt


def parse_packet(ts: float, buf: bytes) -> dict | None:
    try:
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            return None
        ip = eth.data
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            return {
                "timestamp": ts,
                "protocol":  "TCP",
                "src_ip":    socket.inet_ntoa(ip.src),
                "dst_ip":    socket.inet_ntoa(ip.dst),
                "src_port":  tcp.sport,
                "dst_port":  tcp.dport,
                "flags":     tcp.flags,
                "length":    ip.len,
            }
        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            return {
                "timestamp": ts,
                "protocol":  "UDP",
                "src_ip":    socket.inet_ntoa(ip.src),
                "dst_ip":    socket.inet_ntoa(ip.dst),
                "src_port":  udp.sport,
                "dst_port":  udp.dport,
                "flags":     None,
                "length":    ip.len,
            }
        elif isinstance(ip.data, dpkt.icmp.ICMP):
            icmp = ip.data
            return {
                "timestamp": ts,
                "protocol":  "ICMP",
                "src_ip":    socket.inet_ntoa(ip.src),
                "dst_ip":    socket.inet_ntoa(ip.dst),
                "src_port":  None,
                "dst_port":  None,
                "flags":     None,
                "icmp_type": icmp.type,
                "icmp_code": icmp.code,
                "length":    ip.len,
            }
        return None
    except Exception:
        return None