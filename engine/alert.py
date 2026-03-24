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
    evidence: dict