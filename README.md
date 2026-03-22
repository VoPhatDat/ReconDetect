# ReconDetect — Tài liệu dự án (đang phát triển)
## Hệ thống phát hiện tấn công quét mạng chủ động (Active Network Scanning Detection)

---

## 1. Tổng quan dự án

Hệ thống phát hiện các loại tấn công reconnaissance chủ động (active recon) dựa trên phân tích lưu lượng mạng. Hệ thống gồm 2 stage:

- **Stage 1 — Rule Engine**: Phát hiện các loại scan phổ biến bằng rule cố định
- **Stage 2 — ML Engine** *(chưa làm)*: Phát hiện slow scan, decoy scan bằng Isolation Forest

---

## 2. Kiến trúc hệ thống

```
Network Traffic
      ↓
  Collector          ← Thu thập packets (file PCAP hoặc live capture)
      ↓
  Normalizer         ← Gom flow, trích xuất feature
      ↓
  Rule Engine        ← So khớp rule, tạo Alert   (Stage 1)
  ML Engine          ← Anomaly detection          (Stage 2 - chưa làm)
      ↓
  Logger/Reporter    ← Xuất kết quả
```
Sơ đồ kiến trúc
<img width="998" height="594" alt="image" src="https://github.com/user-attachments/assets/4272d891-6867-463a-8ab6-79ec5982054e" />
---
---

## 3. Cấu trúc thư mục

```
recon_detector/
├── config/
│   └── config.json          # cấu hình TShark path, interface
├── collector/
│   ├── __init__.py
│   ├── platform.py          # tìm TShark từ config.json
│   ├── parser.py            # parse raw bytes → dict
│   ├── pcap_reader.py       # đọc file pcap/pcapng → yield packet
│   └── live_capture.py      # TShark subprocess → yield packet
├── normalizer/
│   ├── __init__.py
│   ├── flow_builder.py      # gom packet theo src_ip
│   └── extractor.py         # tính feature từ flow
├── engine/                  # chưa làm
│   ├── __init__.py
│   ├── rule_loader.py
│   ├── rule_matcher.py
│   └── alert.py
├── rules/                   # chưa làm
│   └── recon_rules.yaml
├── output/                  # chưa làm
│   └── reporter.py
├── tests/
├── pcap/
└── main.py
```

---

## 4. Chi tiết từng module

### 4.1 config/config.json

```json
{
    "tshark_path": "C:\\Program Files\\Wireshark\\tshark.exe",
    "default_interface": "5"
}
```

---

### 4.2 Collector

**Công nghệ**: TShark (capture) + dpkt (parse)

**Lý do chọn**:
- TShark chạy ở tốc độ C, bắt gói tin song song với Python qua subprocess
- dpkt parse bytes nhanh hơn Scapy ~10x
- Hỗ trợ scale đến 100k packets/giây

#### collector/platform.py

```python
import json
import subprocess
from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.json"

def load_config() -> dict
def get_tshark_path() -> str      # đọc từ config.json, raise nếu không tìm thấy
def list_interfaces() -> list[dict]  # chạy tshark -D, parse output
def print_interfaces()               # in danh sách interface
```

#### collector/parser.py

```python
import socket
import dpkt

def parse_packet(ts: float, buf: bytes) -> dict | None
```

Output dict:
```python
# TCP
{"timestamp": ts, "protocol": "TCP", "src_ip": "...", "dst_ip": "...",
 "src_port": int, "dst_port": int, "flags": int, "length": int}

# UDP
{"timestamp": ts, "protocol": "UDP", "src_ip": "...", "dst_ip": "...",
 "src_port": int, "dst_port": int, "flags": None, "length": int}

# ICMP
{"timestamp": ts, "protocol": "ICMP", "src_ip": "...", "dst_ip": "...",
 "src_port": None, "dst_port": None, "flags": None,
 "icmp_type": int, "icmp_code": int, "length": int}
```

**Lưu ý**: `flags` là số nguyên (bitmask). Decode:
```
FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20
SYN only = 2, ACK only = 16, SYN+ACK = 18, NULL = 0, XMAS = 41
```

#### collector/pcap_reader.py

```python
def _detect_format(path: Path) -> str   # đọc magic bytes, trả "pcap" hoặc "pcapng"
def read(filepath: str)                  # generator → yield packet dict
```

Magic bytes:
```
pcapng: 0a 0d 0d 0a
pcap:   d4 c3 b2 a1  hoặc  a1 b2 c3 d4
```

#### collector/live_capture.py

```python
def capture(interface: str | None = None, packet_count: int = 0)
# generator → yield packet dict
# interface=None → đọc từ config.json
# packet_count=0 → chạy mãi
```

Hoạt động:
```
TShark subprocess (capture C speed)
    ↓ stdout pipe raw bytes
dpkt.pcap.Reader (parse)
    ↓
yield packet dict → Normalizer
```

---

### 4.3 Normalizer

#### normalizer/flow_builder.py

Gom packet theo `src_ip` vào flow dict.

```python
class flow_builder:
    def __init__(self)
    def _new_flow(self) -> dict
    def _count_flags(self, flow, flags)
    def add_packet(self, pkt: dict)
    def get_flows(self) -> dict
```

Flow structure:
```python
{
    'dst_ips':    set(),    # set IP bị quét
    'ports':      set(),    # set port bị quét (không trùng)
    'port_list':  [],       # list port (giữ tần suất cho entropy)
    'timestamps': [],       # list thời gian
    'syn_count':  0,
    'ack_count':  0,
    'fin_count':  0,
    'rst_count':  0,
    'null_count': 0,
    'xmas_count': 0,
    'icmp_echo':  0,
}
```

Logic đếm flags (bitwise AND):
```python
flags == 0                              → null_count
(flags & 0x29) == 0x29                  → xmas_count  (FIN+PSH+URG)
(flags & 0x02) and not (flags & 0x10)  → syn_count   (SYN, không ACK)
(flags & 0x10) and not (flags & 0x02)  → ack_count   (ACK, không SYN)
flags & 0x01                            → fin_count
flags & 0x04                            → rst_count
```

#### normalizer/extractor.py

Tính feature từ flow cho Rule Engine.

```python
def _entropy(data: list) -> float        # Shannon entropy
def extract(src_ip: str, flow: dict) -> dict
def extract_all(flows: dict) -> list[dict]
```

Feature dict output:
```python
{
    'src_ip':       str,
    'port_count':   int,      # len(ports)
    'dst_ip_count': int,      # len(dst_ips)
    'duration':     float,    # max(ts) - min(ts)
    'syn_count':    int,
    'ack_count':    int,
    'rst_count':    int,
    'fin_count':    int,
    'null_count':   int,
    'xmas_count':   int,
    'icmp_echo':    int,
    'ack_ratio':    float,    # ack / syn
    'rst_ratio':    float,    # rst / syn
    'pkt_per_sec':  float,    # syn / duration
    'avg_interval': float,    # duration / len(timestamps)
    'port_entropy': float,    # Shannon entropy của port_list
}
```

Edge cases:
```
syn_count = 0  → ack_ratio = 0, rst_ratio = 0
duration = 0   → pkt_per_sec = 0
timestamps < 2 → bỏ qua flow đó (lọc trong extract_all)
port_list < 2  → entropy = 0
```

**Shannon Entropy**:
```
H = -Σ p(x) × log2(p(x))

H thấp → port lặp lại nhiều → traffic bình thường
H cao  → port đều nhau     → tool scan tự động
```

---

## 5. Các loại tấn công cần detect (Stage 1)

| Loại scan | Flag | Đặc trưng | Rule |
|---|---|---|---|
| SYN scan | SYN (0x02) | port_count cao, ack_ratio thấp, nhanh | port_count>20, ack_ratio<0.3, duration<5 |
| Slow scan | SYN (0x02) | giống SYN nhưng chậm | port_count>20, ack_ratio<0.3, duration>30 |
| NULL scan | 0x00 | không có flag | null_count>5 |
| XMAS scan | 0x29 | FIN+PSH+URG | xmas_count>5 |
| FIN scan | 0x01 | chỉ FIN | fin_count>5, ack_ratio<0.3 |
| Ping sweep | ICMP type=8 | nhiều IP | icmp_echo>10, dst_ip_count>10 |
| UDP scan | UDP | nhiều port UDP | port_count>20, protocol=UDP |

---

## 6. Rule Engine (chưa làm)

### 6.1 Cấu trúc

```
engine/
├── rule_loader.py    # đọc rules/recon_rules.yaml
├── rule_matcher.py   # so khớp feature với rule
└── alert.py          # Alert dataclass
```

### 6.2 rules/recon_rules.yaml

```yaml
rules:
  - id: R001
    name: SYN Port Scan
    severity: HIGH
    conditions:
      port_count: { gt: 20 }
      ack_ratio:  { lt: 0.3 }
      duration:   { lt: 5 }

  - id: R002
    name: Slow and Low Scan
    severity: MEDIUM
    conditions:
      port_count: { gt: 20 }
      ack_ratio:  { lt: 0.3 }
      duration:   { gt: 30 }

  - id: R003
    name: NULL Scan
    severity: HIGH
    conditions:
      null_count: { gt: 5 }

  - id: R004
    name: XMAS Scan
    severity: HIGH
    conditions:
      xmas_count: { gt: 5 }

  - id: R005
    name: Ping Sweep
    severity: MEDIUM
    conditions:
      icmp_echo:    { gt: 10 }
      dst_ip_count: { gt: 10 }
```

Operators hỗ trợ: `gt`, `lt`, `gte`, `lte`, `eq`

Điều kiện trong một rule là **AND** — tất cả phải đúng mới trigger.

### 6.3 Alert object

```python
{
    'rule_id':   'R001',
    'rule_name': 'SYN Port Scan',
    'severity':  'HIGH',
    'src_ip':    '192.168.177.134',
    'timestamp': '2024-03-19 10:30:45',
    'evidence':  {
        'port_count': 50,
        'ack_ratio':  0.04,
        'duration':   2.3,
    }
}
```

---

## 7. Bypass techniques và giới hạn

### Stage 1 counter được
- Fast SYN scan
- NULL/XMAS/FIN scan
- Ping sweep
- UDP scan
- Masscan, Zmap

### Stage 1 không counter được
| Kỹ thuật | Lý do | Giải pháp Stage 2 |
|---|---|---|
| Slow scan (-T1) | port_count tích lũy chậm | Isolation Forest + long window |
| Decoy scan (-D) | nhiều src_ip giả | Correlation/Graph analysis |
| Fragmented packets | flags không parse được | Packet reassembly |
| Idle/Zombie scan | src_ip bị giả mạo | IP ID sequence analysis |
| IPv6 | collector chỉ xử lý IPv4 | Thêm dpkt.ip6 |
| App layer recon | traffic trông bình thường | HTTP parser + behavior |

---

## 8. Test output mẫu (TCP_Syn.pcapng)

```
──────────────────────────────────────────────────
  IP:           192.168.177.134
  port_count:   1000
  dst_ip_count: 2
  duration:     4.1905s
  syn_count:    2000
  ack_count:    0
  rst_count:    4
  ack_ratio:    0.0       ← không có handshake → SYN scan
  rst_ratio:    0.002
  pkt_per_sec:  477.2683  ← rất nhanh → nmap default
  avg_interval: 0.0021s
  port_entropy: 9.9638    ← gần max (log2(1000)=9.97) → đều đặn → tool
```

Kết luận: `192.168.177.134` đang thực hiện SYN scan trên 1000 port.

---

## 9. Việc cần làm tiếp theo

```
✅ collector/platform.py
✅ collector/parser.py
✅ collector/pcap_reader.py
✅ collector/live_capture.py
✅ normalizer/flow_builder.py
✅ normalizer/extractor.py
⏳ engine/rule_loader.py
⏳ engine/rule_matcher.py
⏳ engine/alert.py
⏳ rules/recon_rules.yaml
⏳ output/reporter.py
⏳ main.py (kết nối tất cả)
⏳ Stage 2 - ML Engine
```

---

## 10. Môi trường phát triển

- OS: Windows (phát triển), Linux (deploy sau)
- Python: 3.13
- Thư viện: dpkt, pyyaml
- Công cụ: TShark (đi kèm Wireshark), VS Code
- GitHub: https://github.com/VoPhatDat/ReconDetect
