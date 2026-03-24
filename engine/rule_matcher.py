#engine/rule_matcher.py
from datetime import datetime
from engine.alert import Alert

#Kiểm tra toán tử và giá trị điều kiện
def _check_conditions(value: float, op_val: dict) -> bool:
    for operator, threshold in op_val.items():
        if operator == 'gt' and not (value > threshold):
            return False
        elif operator == 'lt' and not (value < threshold):
            return False
        elif operator == 'gte' and not (value >= threshold):
            return False
        elif operator == 'lte' and not (value <= threshold):
            return False
        elif operator == 'eq' and not (value == threshold):
            return False
    return True

#Kiểm tra rule có match hay không
def _check_rule(features:dict, rule:dict) -> bool:
    for feature, op_val in rule["conditions"].items():
        value = features.get(feature, 0)
        if not _check_conditions(value, op_val):
            return False
    return True
        
#Hàm so khớp các rule với features trả về một list Alert (in ra)
def match(features: dict, rules: list[dict]) -> list[Alert]:
    alerts = []
    for rule in rules:
        if _check_rule(features, rule):
            alert = Alert(
                rule_id    = rule["id"],
                rule_name  = rule["name"],
                confidence = rule["confidence"],
                src_ip     = features["src_ip"],
                timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                evidence   = {f: features.get(f, 0) for f in rule["conditions"]},
            )
            alerts.append(alert)
    return alerts