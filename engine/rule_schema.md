# ReconDetect — Rule Schema Documentation

Tài liệu mô tả cấu trúc và các tham số của rule trong `rules/recon_rules.yaml`.

---

## Cấu trúc tổng quát

```yaml
rules:
  - id:         <string>     # bắt buộc
    name:       <string>     # bắt buộc
    confidence: <string>     # bắt buộc
    conditions:              # bắt buộc, ít nhất 1
      <feature>: { <operator>: <value> }
```

---

## Tham số

### `id`
- **Kiểu**: string
- **Bắt buộc**: có
- **Mô tả**: Định danh duy nhất của rule, không được trùng
- **Convention**: `R` + 3 chữ số
- **Ví dụ**: `R001`, `R002`, `R010`

---

### `name`
- **Kiểu**: string
- **Bắt buộc**: có
- **Mô tả**: Tên mô tả loại tấn công, xuất hiện trong Alert
- **Ví dụ**: `SYN Port Scan`, `Ping Sweep`, `NULL Scan`

---

### `confidence`
- **Kiểu**: string — một trong 2 giá trị sau
- **Bắt buộc**: có

| Giá trị | Ý nghĩa | Ví dụ |
|---------|---------|-------|
| `CONFIRMED` | Chắc chắn là scan tool — traffic bình thường không bao giờ có pattern này | NULL scan, XMAS scan, SYN scan |
| `SUSPECTED` | Có thể là scan, có thể là traffic bình thường — cần Stage 2 xác nhận | Ping sweep, Slow scan, UDP scan |

#### Khi nào dùng CONFIRMED?

Hỏi: *"Traffic bình thường có bao giờ có pattern này không?"*

Nếu **không** → dùng `CONFIRMED`.

```
NULL scan  → không có app nào gửi packet không có flag
XMAS scan  → không có app nào gửi FIN+PSH+URG cùng lúc
SYN scan   → không có user thật nào gửi hàng trăm SYN mà không complete handshake
```

#### Khi nào dùng SUSPECTED?

Nếu **có thể** → dùng `SUSPECTED`.

```
Ping sweep → admin cũng ping nhiều máy để check mạng
Slow scan  → traffic chậm bình thường cũng có
UDP scan   → DNS, game, DHCP cũng dùng nhiều port UDP
```

> Flow bị gắn `SUSPECTED` sẽ được đưa sang **Stage 2 ML Engine** để xác nhận thêm.

---

### `conditions`
- **Kiểu**: dict
- **Bắt buộc**: có, ít nhất 1 field
- **Logic**: Tất cả điều kiện là **AND** — mọi điều kiện phải đúng mới trigger alert

Cú pháp:
```yaml
conditions:
  <feature_name>: { <operator>: <value> }
```

---

## Operators

| Operator | Ý nghĩa | Ví dụ |
|----------|---------|-------|
| `gt`  | lớn hơn (>)            | `{ gt: 20 }`  |
| `lt`  | nhỏ hơn (<)            | `{ lt: 0.3 }` |
| `gte` | lớn hơn hoặc bằng (>=) | `{ gte: 10 }` |
| `lte` | nhỏ hơn hoặc bằng (<=) | `{ lte: 5 }`  |
| `eq`  | bằng (==)              | `{ eq: 1024 }`|

---

## Features có thể dùng trong conditions

Các feature này được tính bởi `normalizer/extractor.py` từ flow của từng `src_ip`.

### Thống kê cơ bản

| Feature | Kiểu | Mô tả |
|---------|------|-------|
| `port_count` | int | Số port đích không trùng nhau |
| `dst_ip_count` | int | Số IP đích không trùng nhau |
| `duration` | float | Thời gian từ packet đầu đến packet cuối (giây) |

### Flag counters

| Feature | Kiểu | Mô tả |
|---------|------|-------|
| `syn_count` | int | Số packet SYN (không có ACK) |
| `ack_count` | int | Số packet ACK (không có SYN) |
| `rst_count` | int | Số packet RST |
| `fin_count` | int | Số packet FIN |
| `null_count` | int | Số packet không có flag nào (flags = 0x00) |
| `xmas_count` | int | Số packet XMAS (FIN+PSH+URG = 0x29) |
| `icmp_echo` | int | Số packet ICMP Echo Request (type=8) |

### Tỷ lệ và tốc độ

| Feature | Kiểu | Mô tả | Ghi chú |
|---------|------|-------|---------|
| `ack_ratio` | float | ack_count / syn_count | 0 nếu syn_count = 0 |
| `rst_ratio` | float | rst_count / syn_count | 0 nếu syn_count = 0 |
| `pkt_per_sec` | float | syn_count / duration | 0 nếu duration = 0 |
| `avg_interval` | float | duration / số packet | giây/packet |

### Entropy

| Feature | Kiểu | Mô tả |
|---------|------|-------|
| `port_entropy` | float | Shannon entropy của danh sách port đích |

Diễn giải `port_entropy`:
- **Thấp** → port lặp lại nhiều → traffic bình thường
- **Cao** → port đều nhau → tool scan tự động
- Max lý thuyết: `log2(port_count)`

---

## Ví dụ rule đầy đủ

```yaml
rules:
  - id: R001
    name: SYN Port Scan
    confidence: CONFIRMED
    conditions:
      port_count: { gt: 20 }
      ack_ratio:  { lt: 0.3 }
      duration:   { lt: 5 }

  - id: R002
    name: Slow and Low Scan
    confidence: SUSPECTED
    conditions:
      port_count: { gt: 20 }
      ack_ratio:  { lt: 0.3 }
      duration:   { gt: 30 }

  - id: R003
    name: NULL Scan
    confidence: CONFIRMED
    conditions:
      null_count: { gt: 5 }

  - id: R004
    name: XMAS Scan
    confidence: CONFIRMED
    conditions:
      xmas_count: { gt: 5 }

  - id: R005
    name: FIN Scan
    confidence: CONFIRMED
    conditions:
      fin_count: { gt: 5 }
      ack_ratio: { lt: 0.3 }

  - id: R006
    name: Ping Sweep
    confidence: SUSPECTED
    conditions:
      icmp_echo:    { gt: 10 }
      dst_ip_count: { gt: 10 }

  - id: R007
    name: UDP Port Scan
    confidence: SUSPECTED
    conditions:
      port_count: { gt: 20 }
```

---

## Lưu ý khi viết rule mới

- `id` phải unique, không được trùng
- Mỗi condition là AND — càng nhiều condition thì càng ít false positive nhưng cũng dễ miss
- Với rule có `duration`: cần PCAP đủ dài để tích lũy flow — rule slow scan cần session nhiều giây
- `port_entropy` nên kết hợp với `port_count` vì entropy thấp khi ít data
- Feature nào không có trong `extractor.py` thì rule sẽ bị lỗi khi load → kiểm tra trước khi thêm
- `CONFIRMED` → alert ngay | `SUSPECTED` → đưa sang Stage 2

---

## Giới hạn hiện tại (Stage 1)

| Kỹ thuật bypass | Lý do không detect được | Giải pháp |
|----------------|------------------------|-----------|
| Slow scan T0 (-T0) | Flow tích lũy quá chậm, không đủ trong 1 session | Stage 2 ML |
| Decoy scan (-D) | Nhiều src_ip giả, không phân biệt được | Stage 2 ML |
| Fragmented packets | dpkt không reassemble fragment | Packet reassembly |
| Idle/Zombie scan | src_ip bị giả mạo | IP ID sequence analysis |

→ Các kỹ thuật trên cần **Stage 2 ML Engine** để xử lý.