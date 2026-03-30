# ReconDetect — Rule Schema Documentation

Tài liệu chi tiết về cấu trúc và các tham số của rule trong `rules/recon_rules.yaml` cho ReconDetect Stage 1 Engine.

---

## Cấu trúc tổng quát

```yaml
rules:
  - id:         <string>     # bắt buộc
    name:       <string>     # bắt buộc
    confidence: <string>     # bắt buộc (CONFIRMED | SUSPECTED)
    conditions:              # bắt buộc, ít nhất 1
      <feature>: { <operator>: <threshold> }
      <feature2>: { <operator>: <threshold> }
```

**Lưu ý**: Tất cả điều kiện (`conditions`) là logic **AND** — mỗi condition phải đúng cùng lúc mới trigger alert.

---

## Tham số cơ bản

### `id`
- **Kiểu**: string
- **Bắt buộc**: YES
- **Constraint**: Unique, không được trùng
- **Convention**: `R` + 3 chữ số (ví dụ: R001, R200, R290)

---

### `name`
- **Kiểu**: string
- **Bắt buộc**: YES
- **Mô tả**: Tên mô tả loại tấn công, xuất hiện trong console + file log
- **Ví dụ**: `SYN Scan`, `Massive Host Discovery`, `NULL Scan`

---

### `confidence`
- **Kiểu**: string — một trong 2 giá trị
- **Bắt buộc**: YES
- **Giá trị hợp lệ**: `CONFIRMED`, `SUSPECTED`

#### CONFIRMED vs SUSPECTED

| Giá trị | Ý nghĩa | Traffic bình thường | Ví dụ |
|---------|---------|-------------------|-------|
| **CONFIRMED** | Chắc chắn là recon tool | Không bao giờ | NULL scan, XMAS scan, FIN scan |
| **SUSPECTED** | Có thể là scan, có thể bình thường | Có thể xảy ra | Ping sweep, UDP scan, Slow scan |

#### Hỏi nhanh: CONFIRMED hay SUSPECTED?

**Q**: Traffic bình thường có bao giờ có pattern này không?

- **Không** → `CONFIRMED`
  - NULL scan: Ứng dụng nào gửi packet flags=0x00? (Không)
  - XMAS scan: Ứng dụng nào gửi FIN+PSH+URG cùng lúc? (Không)
  - SYN scan: User thật nào gửi hàng trăm SYN mà không complete handshake? (Không)

- **Có thể** → `SUSPECTED`
  - Ping sweep: Admin cũng ping nhiều máy để check network
  - Slow scan: Traffic chậm bình thường cũng tồn tại
  - UDP scan: DNS, game, DHCP cũng dùng nhiều port UDP

**Flow bị gắn SUSPECTED sẽ được đưa sang Stage 2 ML Engine để xác nhận thêm.**

---

### `conditions`
- **Kiểu**: dict
- **Bắt buộc**: YES, ít nhất 1 field
- **Logic**: AND — tất cả điều kiện phải đúng
- **Cú pháp**:
  ```yaml
  conditions:
    <feature_name>: { <operator>: <threshold> }
  ```

---

## Operators

| Operator | Ý nghĩa | Ví dụ |
|----------|---------|-------|
| `gt`  | Lớn hơn (>)            | `{ gt: 20 }` |
| `lt`  | Nhỏ hơn (<)            | `{ lt: 0.3 }` |
| `gte` | Lớn hơn hoặc bằng (>=) | `{ gte: 10 }` |
| `lte` | Nhỏ hơn hoặc bằng (<=) | `{ lte: 5 }` |
| `eq`  | Bằng (==)              | `{ eq: 1024 }` |

---

## Features (Danh sách đầy đủ)

Các feature này được tính bởi `normalizer/extractor.py` từ flow của từng `src_ip` trong cửa sổ thời gian hiện tại.

### 1. Host & Port Counting

| Feature | Kiểu | Mô tả | Ghi chú |
|---------|------|-------|---------|
| `dst_ip_count` | int | Số IP đích **không trùng nhau** trong session | Ping sweep, massive scan có giá trị cao |
| `port_count` | int | Số port đích **không trùng nhau** | Port scan → cao |
| `tcp_port_count` | int | Số port TCP không trùng | TCP-only metric, tránh ảnh hưởng UDP |
| `udp_port_count` | int | Số port UDP không trùng | UDP-only metric |
| `udp_packet_count` | int | Tổng packet UDP (tính cả lặp) | Để phân biệt UDP scan vs traffic bình thường |

### 2. Thời gian

| Feature | Kiểu | Mô tả | Công thức | Ứng dụng |
|---------|------|-------|-----------|---------|
| `duration` | float | Thời gian từ packet đầu → cuối (giây) | ts_max - ts_min | Phát hiện scan nhanh vs chậm |
| `avg_interval` | float | Thời gian trung bình giữa các packet | duration / (n_packets - 1) | Scan đều đặn vs bùng nổ |
| `pkt_per_sec` | float | Số packet/giây | n_packets / duration | Tốc độ gửi gói |

### 3. TCP Flags

| Feature | Kiểu | Mô tả |
|---------|------|-------|
| `syn_count` | int | SYN nhưng **không** ACK (flags có 0x02, không có 0x10) |
| `ack_count` | int | ACK nhưng **không** SYN (flags có 0x10, không có 0x02) |
| `rst_count` | int | RST (flags có 0x04) |
| `fin_count` | int | FIN-only (flags == 0x01, không kèm khác) |
| `null_count` | int | Flags = 0x00 (không có flag nào) |
| `xmas_count` | int | XMAS = FIN+PSH+URG (flags == 0x29) |

### 4. Tỷ lệ & Entropy

| Feature | Kiểu | Mô tả | Ghi chú |
|---------|------|-------|---------|
| `ack_ratio` | float | ack_count / syn_count | 0 nếu syn_count=0; thấp = SYN scan |
| `rst_ratio` | float | rst_count / syn_count | 0 nếu syn_count=0 |
| `port_entropy` | float | Shannon entropy của port list | Cao = port đều → scan tool |
| `tcp_port_entropy` | float | Entropy của **TCP port** only | Tránh ảnh hưởng UDP |
| `udp_port_entropy` | float | Entropy của **UDP port** only | Tránh ảnh hưởng TCP |

**Diễn giải entropy:**
```
Thấp (< 2)   → port lặp lại nhiều → traffic bình thường
Cao (> 5)    → port đều nhau → scan tool
Công thức    → Shannon entropy: -Σ(p * log2(p))
```

### 5. ICMP & ARP

| Feature | Kiểu | Mô tả |
|---------|------|-------|
| `icmp_echo` | int | ICMP Echo Request (type=8) — ping |
| `arp_request` | int | ARP Request (opcode=1) |

### 6. Metadata

| Feature | Kiểu | Mô tả |
|---------|------|-------|
| `packet_count` | int | Tổng packet trong session |
| `timestamp` | string | Timestamp cuối cùng (format: `YYYY-MM-DD HH:MM:SS`) |
| `src_ip` | string | Source IP (tự động thêm vào alert) |

---

## Các rule hiện tại (v2.0)

Danh sách rule từ `recon_rules.yaml`:

### Host Discovery Rules

```yaml
- id: R200
  name: Massive Host Discovery
  confidence: CONFIRMED
  conditions:
    dst_ip_count: { gt: 100 }

- id: R201
  name: Wide Network Scan (Fast)
  confidence: CONFIRMED
  conditions:
    dst_ip_count: { gt: 50 }
    duration: { lt: 30 }
```

### Speed-based Detection

```yaml
- id: R210
  name: Ultra Fast Scan (Masscan/ZMap)
  confidence: CONFIRMED
  conditions:
    pkt_per_sec: { gt: 100 }
    dst_ip_count: { gt: 10 }
    syn_count: { gt: 80 }

- id: R211
  name: High Speed Scan (Nmap -T4/-T5)
  confidence: CONFIRMED
  conditions:
    pkt_per_sec: { gt: 50 }
    duration: { lt: 10 }
    port_count: { gt: 20 }
    syn_count: { gt: 60 }
    ack_ratio: { lt: 0.6 }

- id: R212
  name: Medium Speed Scan
  confidence: SUSPECTED
  conditions:
    pkt_per_sec: { gt: 20 }
    tcp_port_count: { gt: 30 }
    tcp_port_entropy: { gt: 4 }
    syn_count: { gt: 60 }
    dst_ip_count: { gt: 2 }

- id: R213
  name: Burst Scan
  confidence: CONFIRMED
  conditions:
    pkt_per_sec: { gt: 80 }
    duration: { lt: 5 }
    dst_ip_count: { gt: 5 }
```

### Protocol Sweeps

```yaml
- id: R220
  name: ICMP Sweep Aggressive
  confidence: CONFIRMED
  conditions:
    icmp_echo: { gt: 30 }
    dst_ip_count: { gt: 20 }

- id: R230
  name: ARP Massive Sweep
  confidence: CONFIRMED
  conditions:
    arp_request: { gt: 50 }
    dst_ip_count: { gt: 50 }
```

### Full Port Scan

```yaml
- id: R240
  name: Full Port Scan
  confidence: CONFIRMED
  conditions:
    port_count: { gt: 1000 }
```

### Stealth Scans

```yaml
- id: R250
  name: SYN Scan (Nmap -sS)
  confidence: CONFIRMED
  conditions:
    syn_count: { gt: 80 }
    ack_ratio: { lt: 0.3 }
    tcp_port_entropy: { gt: 3 }

- id: R270
  name: NULL Scan
  confidence: CONFIRMED
  conditions:
    null_count: { gt: 10 }

- id: R271
  name: XMAS Scan
  confidence: CONFIRMED
  conditions:
    xmas_count: { gt: 10 }

- id: R272
  name: FIN Scan
  confidence: CONFIRMED
  conditions:
    fin_count: { gt: 10 }
    syn_count: { lt: 5 }
```

### UDP & Entropy-based

```yaml
- id: R260
  name: UDP Port Scan (Broad)
  confidence: CONFIRMED
  conditions:
    udp_port_count: { gt: 30 }
    udp_packet_count: { gt: 60 }
    udp_port_entropy: { gt: 4 }
    syn_count: { lt: 5 }

- id: R261
  name: UDP Scan (Moderate)
  confidence: SUSPECTED
  conditions:
    udp_port_count: { gt: 15 }
    udp_packet_count: { gt: 30 }
    dst_ip_count: { gt: 1 }
    syn_count: { lt: 5 }

- id: R280
  name: High Entropy Port Scan
  confidence: CONFIRMED
  conditions:
    tcp_port_entropy: { gt: 6 }
    tcp_port_count: { gt: 30 }
    syn_count: { gt: 60 }

- id: R290
  name: Recon Chain (Sweep + Port Scan)
  confidence: CONFIRMED
  conditions:
    dst_ip_count: { gt: 15 }
    port_count: { gt: 30 }
```

---

## Hướng dẫn viết rule mới

### Bước 1: Xác định loại tấn công

Ví dụ: "Tôi muốn detect Nmap SYN scan"

### Bước 2: Liệt kê đặc điểm

Nmap SYN scan có đặc điểm:
- Nhiều SYN → syn_count cao
- Ít ACK response → ack_ratio thấp
- Quét nhiều port → port_count cao

### Bước 3: Chọn confidence

- **CONFIRMED**: SYN scan chắc chắn là tấn công (traffic bình thường không làm vậy)
- Confidence: `CONFIRMED`

### Bước 4: Viết conditions

```yaml
- id: R999
  name: My SYN Scan Detection
  confidence: CONFIRMED
  conditions:
    syn_count: { gt: 80 }
    ack_ratio: { lt: 0.3 }
    port_count: { gt: 20 }
```

### Bước 5: Validate

```bash
python -m engine.rule_loader rules/recon_rules.yaml
# Nếu không lỗi → OK!
```

---

## Lưu ý khi viết rule

### ✅ Best Practices

1. **Dùng AND logic tốt**: Càng nhiều condition → càng ít false positive
   ```yaml
   # ✓ Tốt: 3 điều kiện, cụ thể
   conditions:
     syn_count: { gt: 80 }
     ack_ratio: { lt: 0.3 }
     port_count: { gt: 20 }
   
   # ✗ Xấu: 1 điều kiện, dễ match nhầm
   conditions:
     syn_count: { gt: 10 }
   ```

2. **Kết hợp entropy với port_count**: Entropy thấp khi dữ liệu ít
   ```yaml
   # ✓ Tốt
   conditions:
     port_entropy: { gt: 5 }
     port_count: { gt: 30 }   # đảm bảo có đủ dữ liệu
   
   # ✗ Xấu
   conditions:
     port_entropy: { gt: 5 }  # entropy có thể cao ngẫu nhiên nếu port ít
   ```

3. **TCP vs UDP separation**: Dùng TCP-only features khi detect TCP scan
   ```yaml
   # ✓ Tốt: không bị ảnh hưởng UDP traffic
   conditions:
     tcp_port_count: { gt: 30 }
     tcp_port_entropy: { gt: 4 }
   
   # ✗ Xấu: port_count có thể có UDP, gây hiểu nhầm
   conditions:
     port_count: { gt: 30 }
   ```

4. **Hạn chế false positive**: Kiểm tra feature không bao giờ xảy ra trong traffic bình thường
   ```yaml
   # ✓ CONFIRMED: null_count không bao giờ bình thường
   conditions:
     null_count: { gt: 10 }
   
   # ✓ SUSPECTED: icmp_echo có thể admin ping mạng
   conditions:
     icmp_echo: { gt: 30 }
   ```

### ❌ Tránh những lỗi thường gặp

| Lỗi | Ví dụ | Sửa |
|-----|-------|-----|
| Feature không tồn tại | `slow_scan_rate: { lt: 5 }` | Dùng feature từ danh sách trên |
| Operator sai | `port_count: ~= 50` | Dùng `gt`, `lt`, `gte`, `lte`, `eq` |
| Confidence sai | `confidence: MAYBE` | Dùng `CONFIRMED` hoặc `SUSPECTED` |
| Logic không rõ | Cơ chế AND không ghi chú | Luôn document tại sao |
| ID trùng | `id: R250` (đã tồn tại) | Dùng ID unique |

---

## Tuning Rule

### Nếu FP cao (False Positive = trigger quá nhiều)

```yaml
# ✗ Quá rộng
conditions:
  port_count: { gt: 10 }

# ✓ Thêm điều kiện
conditions:
  port_count: { gt: 50 }
  ack_ratio: { lt: 0.3 }    # ← thêm dòng này
```

### Nếu FN cao (False Negative = miss scan)

```yaml
# ✗ Quá chặt
conditions:
  port_count: { gt: 1000 }
  syn_count: { gt: 500 }

# ✓ Nới lỏng đi
conditions:
  port_count: { gt: 100 }
  syn_count: { gt: 50 }
```

### Nếu scan chậm

```yaml
# ✗ Không detect slow scan
conditions:
  pkt_per_sec: { gt: 100 }

# ✓ Thêm rule cho slow scan
- id: R213
  name: Slow Scan Detection
  confidence: SUSPECTED
  conditions:
    duration: { gt: 60 }
    port_count: { gt: 30 }
    ack_ratio: { lt: 0.3 }
```

---

## Giới hạn Stage 1 & Cách vượt qua

| Kỹ thuật bypass | Lý do Stage 1 không detect | Giải pháp |
|----------------|---------------------------|----------|
| **Slow scan** (-T0) | Flow tích lũy quá chậm, có thể không đủ trong 1 window | Tăng `window_seconds` hoặc rule SUSPECTED cho Stage 2 |
| **Decoy scan** (-D) | Nhiều src_ip giả, không phân biệt từng attacker | Stage 2 ML: phân tích IP reputation |
| **Fragmented packets** | dpkt không reassemble fragment tự động | Cần packet reassembly layer (nâng cấp future) |
| **Idle/Zombie scan** | src_ip bị fake qua protocol | IP ID sequence analysis (Stage 2) |
| **Spoofed ARP** | ARP request có thể bị fake | ARP-specific validation rules (future) |

→ **Tất cả các trường hợp trên sẽ được xử lý bởi Stage 2 ML Engine.**

---

## Debugging Rule

### Kiểm tra rule syntax

```bash
# Load rule file (sẽ print lỗi nếu có)
python -c "from engine.rule_loader import load_rules; print(load_rules('rules'))"
```

### Test rule trên PCAP

```bash
# Run mode pcap
python main.py --mode pcap --pcap-path <file.pcapng>
```

### Xem output chi tiết

```
[10:45:23] 🔴 CONFIRMED | R250 | SYN Scan (Nmap -sS)
src_ip=192.168.1.100
timestamp=2025-01-15 10:45:23
Matched conditions:
  - syn_count > 80  => actual=150
  - ack_ratio < 0.3  => actual=0.05
  - tcp_port_entropy > 3  => actual=6.2
Context (metrics in current window):
  port_count=500, dst_ip_count=1, duration=45.2, pkt_per_sec=11.1, ...
```

**Nếu rule trigger nhầm**, kiểm tra:
1. Các feature `actual` có hợp lý không?
2. Có cần thêm condition để loại trừ traffic bình thường?
3. Ngưỡng (`threshold`) có quá thấp không?

---

## Example: Custom Intrusion Scenario

**Scenario**: Detect attacker chạy Nmap -sU (UDP scan) trên subnet

```yaml
- id: R312
  name: Aggressive UDP Sweep (Nmap -sU)
  confidence: CONFIRMED
  conditions:
    udp_port_count: { gt: 40 }        # quét 40+ port UDP
    udp_packet_count: { gt: 80 }      # ít nhất 80 packet UDP
    dst_ip_count: { gt: 5 }           # quét 5+ destination
    syn_count: { lt: 3 }              # không phải TCP (phân biệt rõ)
    udp_port_entropy: { gt: 5 }       # port đều → tool
```

**Giải thích**:
- `udp_port_count > 40`: Port UDP riêng lẻ (không trùng)
- `udp_packet_count > 80`: Tổng packet (tính cả lặp) — UDP có retry
- `dst_ip_count > 5`: Phải quét nhiều IP
- `syn_count < 3`: Hầu như không có TCP → rõ ràng là UDP scan
- `udp_port_entropy > 5`: Port random, không phải traffic bình thường

---

## FAQ

**Q: Tại sao rule tôi không trigger?**
A: Kiểm tra:
1. Feature có support không? (xem danh sách trên)
2. Dữ liệu PCAP có đủ không? (ít nhất 2 packet từ cùng src_ip)
3. Threshold có quá cao không? (rule R250: syn_count > 80 có thể miss slow scan)
4. Feature logic có đúng không? (vd: ack_ratio = ack_count/syn_count, nếu syn=0 thì ratio=0)

**Q: Port entropy bao cao?**
A: Phụ thuộc port count:
```
Port count=10, entropy ngẫu nhiên ≈ 3.3
Port count=50, entropy ngẫu nhiên ≈ 5.6
Port count=100, entropy ngẫu nhiên ≈ 6.6
```
Dùng `port_entropy > 5` + `port_count > 30` để an toàn.

**Q: Duration = 0 xảy ra khi nào?**
A: Khi có duy nhất 1 packet từ src_ip trong window. Extractor chỉ export nếu `len(timestamps) >= 2`.

**Q: Làm sao biết alert là từ rule nào?**
A: Xem `rule_id` trong output, ví dụ `R250` → SYN Scan.

---

## Liên kết & Tài liệu

- **extractor.py**: Định nghĩa features và công thức tính toán
- **rule_loader.py**: Validate rule syntax
- **rule_matcher.py**: Match logic (AND cho conditions)
- **recon_rules.yaml**: Danh sách rule hiện tại (v2.0)

---

**Last Updated**: 2025-03-30  
**ReconDetect Engine**: v2.0 (Stage 1 Rules)