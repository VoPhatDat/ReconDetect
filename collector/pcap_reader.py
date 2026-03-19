# collector/pcap_reader.py
import socket
import dpkt
from pathlib import Path
import sys
from collector.parser import parse_packet
sys.stdout.reconfigure(encoding='utf-8')

def _detech_format(path: Path) -> str:
	with open(path, "rb") as f:
		magicbyte = f.read(4)
	if magicbyte == b'\x0a\x0d\x0d\x0a':
		return "pcapng"
	elif magicbyte in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
		return "pcap"
	else:
		raise ValueError(f"File không phải pcap hoặc pcapng: {path}")

def read(filepath: str):
	path = Path(filepath)

	if not path.exists():
		raise FileNotFoundError(f"Không tìm thấy file: {filepath}")

	formatcheck = _detech_format(path)

	with open(path, "rb") as f:
		reader = dpkt.pcapng.Reader(f) if formatcheck == "pcapng" else dpkt.pcap.Reader(f)
		for ts, buf in reader:
			pkt = parse_packet(ts, buf)
			if pkt is None:
				continue
			yield pkt

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Lỗi: chưa nhập đường dẫn file PCAP.")
        print("Cách dùng: python -m collector.pcap_reader <đường dẫn file>")
        print("Ví dụ:     python -m collector.pcap_reader pcap/TCP_Syn.pcapng")
        sys.exit(1)

    filepath = sys.argv[1]
    print(f"Đọc file: {filepath}\n")
    for i, pkt in enumerate(read(filepath), start=1):
        print(f"[{i}] {pkt}")