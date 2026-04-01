# output/reporter.py
from __future__ import annotations

from datetime import datetime

from engine.alert import Alert

_TABLE_HEADER_PRINTED = False

def _format_conditions(alert: Alert) -> str:
    lines = []
    # conditions: { feature: { op: value, ... } }
    for feature, op_map in alert.conditions.items():
        actual = alert.evidence.get(feature, 0)
        for op, threshold in op_map.items():
            lines.append(f"  - {feature} {op} {threshold}  => actual={actual}")
    return "\n".join(lines)


def _format_context(alert: Alert) -> str:
    # Chỉ hiển thị các metric context đã được engine/rule_matcher cung cấp
    if not alert.context:
        return ""

    # Trật tự hiển thị: các key quan trọng trước
    preferred_order = [
        "port_count",
        "tcp_port_count",
        "udp_port_count",
        "dst_ip_count",
        "duration",
        "pkt_per_sec",
        "port_entropy",
        "tcp_port_entropy",
        "udp_port_entropy",
        "udp_packet_count",
        "syn_count",
        "ack_count",
        "rst_count",
        "fin_count",
        "null_count",
        "xmas_count",
        "icmp_echo",
        "arp_request",
        "ack_ratio",
        "rst_ratio",
        "avg_interval",
    ]

    ordered_keys = [k for k in preferred_order if k in alert.context] + [
        k for k in alert.context.keys() if k not in preferred_order
    ]

    parts = [f"{k}={alert.context.get(k)}" for k in ordered_keys]
    return "  " + ", ".join(parts)


def format_alert(alert: Alert) -> str:
    conf = "CONFIRMED" if alert.confidence == "CONFIRMED" else "SUSPECTED"
    icon = "🔴" if alert.confidence == "CONFIRMED" else "🟡"

    latest_clock = alert.timestamp[-8:] if alert.timestamp else datetime.now().strftime("%H:%M:%S")

    return (
        f"[{latest_clock}] {icon} {conf} | {alert.rule_id} | {alert.rule_name}\n"
        f"src_ip={alert.src_ip}\n"
        f"timestamp={alert.timestamp}\n"
        f"Matched conditions:\n"
        f"{_format_conditions(alert)}\n"
        f"Context (metrics in current window):\n"
        f"{_format_context(alert)}\n"
        + "-" * 90
    )


def _short_reason(alert: Alert) -> str:
    parts = []
    for feature, op_map in alert.conditions.items():
        actual = alert.evidence.get(feature, 0)
        for op, threshold in op_map.items():
            parts.append(f"{feature}{op}{threshold}(a={actual})")
    return "; ".join(parts)


def _clip(text: str, width: int) -> str:
    if len(text) <= width:
        return text.ljust(width)
    return (text[: max(0, width - 1)] + "…")


def _table_header() -> str:
    return (
        f"{'TIME':<8} | {'SEV':<4} | {'RULE':<4} | {'SRC_IP':<15} | "
        f"{'RULE_NAME':<24} | WHY"
    )


def format_alert_oneline(alert: Alert) -> str:
    """
    Alert gọn 1 dòng để hiển thị realtime trên console.
    """
    latest_clock = alert.timestamp[-8:] if alert.timestamp else datetime.now().strftime("%H:%M:%S")
    # Tránh emoji để tương thích CMD/PowerShell font/encoding.
    conf = "CONF" if alert.confidence == "CONFIRMED" else "SUSP"
    short_reason = _short_reason(alert)
    return (
        f"{latest_clock:<8} | {conf:<4} | {alert.rule_id:<4} | {alert.src_ip:<15} | "
        f"{_clip(alert.rule_name, 24)} | {short_reason}"
    )


def _append_to_txt(path: str, text: str) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(text)
        f.write("\n")


def report(
    alerts: list[Alert],
    output_txt_path: str | None = None,
    quiet_if_empty: bool = True,
    one_line_console: bool = False,
    reset_table_header: bool = False,
) -> None:
    """
    In alert theo thời gian thực (console) và tùy chọn ghi ra file txt.
    """
    global _TABLE_HEADER_PRINTED
    if reset_table_header:
        _TABLE_HEADER_PRINTED = False
    
    if not alerts:
        if not quiet_if_empty:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ No alerts detected.")
        return

    for alert in alerts:
        console_text = format_alert_oneline(alert) if one_line_console else format_alert(alert)
        if one_line_console and not _TABLE_HEADER_PRINTED:
            print(_table_header())
            print("-" * 120)
            _TABLE_HEADER_PRINTED = True
        print(console_text)
        if output_txt_path:
            # File log luôn ghi bản đầy đủ để phục vụ hậu kiểm.
            _append_to_txt(output_txt_path, format_alert(alert))