#engine/rule_loader.py
import yaml
from pathlib import Path

from normalizer.extractor import SUPPORTED_FEATURES

VALID_CONFIDENCES = {"CONFIRMED", "SUSPECTED"}
VALID_OPERATORS = {"gt", "lt","gte","lte", "eq"}

def _validate_rule(rule: dict):
    #check đủ các field bắt buộc
    for field in ["id", "name", "confidence", "conditions"]:
        if field not in rule:
            raise ValueError(f"Rule '{rule.get('id', '???')}': thiếu field '{field}'")
        
    #check confidence hợp lệ
    if rule["confidence"] not in VALID_CONFIDENCES:
        raise ValueError(f"Rule '{rule['id']}': confidence '{rule['confidence']}' không hợp lệ. Phải là {VALID_CONFIDENCES}")
    
    #check conditions không rỗng
    if not rule["conditions"]:
        raise ValueError(f"Rule '{rule['id']}': conditions không được rỗng")

    # validate feature name trong conditions
    for feature_name in rule["conditions"].keys():
        if feature_name not in SUPPORTED_FEATURES:
            supported_preview = ", ".join(sorted(SUPPORTED_FEATURES)[:10])
            raise ValueError(
                f"Rule '{rule['id']}': feature '{feature_name}' không được hỗ trợ. "
                f"Ví dụ supported: {supported_preview} ..."
            )
    
    #check operator hợp lệ
    for feature, op_val in rule["conditions"].items():
        for operator in op_val.keys():
            if operator not in VALID_OPERATORS:
                raise ValueError(f"Rule '{rule['id']}': operator '{operator}' không hợp lệ")
            
def load_rules(path: str) -> list[dict]:
    rule_path = Path(path)
    if not rule_path.exists():
        raise FileNotFoundError(f"Không tìm thấy rules path: {path}")

    rules: list[dict] = []
    # Hỗ trợ cả 1 file yaml hoặc 1 thư mục chứa nhiều file yaml (để tách rule theo loại scan).
    files = [rule_path] if rule_path.is_file() else sorted(rule_path.glob("*.yaml"))
    if not files:
        raise ValueError(f"Không có file .yaml nào trong: {path}")

    for file in files:
        with open(file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        file_rules = data.get("rules", [])
        if not isinstance(file_rules, list):
            raise ValueError(f"File {file}: key 'rules' phải là list")
        rules.extend(file_rules)

    for rule in rules:
        _validate_rule(rule)

    return rules