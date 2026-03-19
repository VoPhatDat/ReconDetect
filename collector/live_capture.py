# collector/live_capture.py
import socket        # thư viện chuyển đổi địa chỉ IP từ bytes sang dạng đọc được
import subprocess    # thư viện để chạy chương trình khác từ Python (ở đây là TShark)
import dpkt          # thư viện đọc và parse gói tin mạng
from collector.platform import get_tshark_path, load_config  # lấy hàm từ file platform.py
from collector.parser import parse_packet

def capture(interface: str | None = None, packet_count: int = 0):

    # Đọc interface từ config nếu không truyền vào
    if interface is None:
        cfg       = load_config()
        interface = cfg.get("default_interface", "1")

    tshark = get_tshark_path()
    cmd    = [tshark, "-i", interface, "-w", "-", "-F", "pcap"]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,  # ẩn log TShark
    )

    try:
        reader = dpkt.pcap.Reader(proc.stdout)
        count  = 0

        for ts, buf in reader:
            pkt = _parse_packet(ts, buf)

            if pkt is None:
                continue

            yield pkt

            count += 1
            if packet_count and count >= packet_count:
                break

    finally:
        proc.terminate()  # luôn kill TShark khi xong dù lỗi hay không


if __name__ == "__main__":
    from collector.platform import print_interfaces

    print_interfaces()

    print("Bắt 100 gói từ interface mặc định...\n")
    for pkt in capture(packet_count=100):
        print(pkt)