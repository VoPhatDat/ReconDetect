#engine/rule_loader.py
import yaml
from pathlib import Path

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
    
    #check operator hợp lệ
    for feature, op_val in rule["conditions"].items():
        for operator in op_val.keys():
            if operator not in VALID_OPERATORS:
                raise ValueError(f"Rule '{rule['id']}': operator '{operator}' không hợp lệ")
            
def load_rules(path: str) -> list[dict]:
    with open(path, 'r', encoding="utf-8") as f:
        data = yaml.safe_load(f)
    rules = data["rules"]
    
    for rule in rules:
        _validate_rule(rule)
        
    return rules
   
if __name__ == "__main__":
    rules = load_rules("../rules/recon_rules.yaml")
    for rule in rules:
        print(rule["id"], rule["name"]) 