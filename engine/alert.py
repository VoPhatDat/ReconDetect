#engine/alert.py
from dataclasses import dataclass

#tạo dataclass cho Alert
@dataclass
class Alert:
    rule_id: str
    rule_name: str
    confidence: str
    src_ip: str
    timestamp: str
    conditions: dict     # các giá trị ngưỡng từ rule hiển thị lý do match
    evidence: dict       # các giá trị thực tế từ các features
    context: dict        # context chứa một số metric quan trọng để thuyết phục hơn
