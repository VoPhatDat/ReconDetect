<img width="998" height="594" alt="image" src="https://github.com/user-attachments/assets/30014e1b-ec5f-4efd-a303-a68c722cd9ea" /># ReconDetect
Hệ thống phát hiện tấn công trinh sát (reconnaissance) sử dụng rulebase (tương lai hướng đến ML)
kiến trúc hệ thống gồm:
- Collector: thu thập lưu lượng trực tiếp hoặc đã được ghi trong file PCAP
- Normalization: trích xuất những đặc trưng của lưu lượng
- Rule Engine: hệ thống rulebase được xây dựng bao gồm các mẫu được tạo để so khớp với các đặc trưng của lưu lượng
- Alert: Cảnh báo nếu phát hiện tấn công
<img width="998" height="594" alt="image" src="https://github.com/user-attachments/assets/4272d891-6867-463a-8ab6-79ec5982054e" />
Công nghệ sử dụng: Python
- Collector: Tshark, dkpt
