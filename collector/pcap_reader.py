# collector/pcap_reader.py
import socket
import dpkt
from pathlib import Path
import sys
from collector.parser import parse_packet
sys.stdout.reconfigure(encoding='utf-8')

def _detect_format(path: Path) -> str:
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

	formatcheck = _detect_format(path)

	with open(path, "rb") as f:
		reader = dpkt.pcapng.Reader(f) if formatcheck == "pcapng" else dpkt.pcap.Reader(f)
		for ts, buf in reader:
			pkt = parse_packet(ts, buf)
			if pkt is None:
				continue
			yield pkt
