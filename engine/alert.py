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
    # conditions chính là phần ngưỡng từ rule để hiển thị "vì sao match"
    conditions: dict
    # evidence chứa giá trị thực của các feature tham gia vào conditions
    evidence: dict
    # context chứa một số metric quan trọng để thuyết phục hơn
    context: dict