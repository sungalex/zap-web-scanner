"""ZAP Alert → KISA 항목 매핑 엔진"""

from scanner.config import load_kisa_items, load_mapping_rules


def map_alerts_to_items(alerts: list) -> dict:
    """ZAP 경고를 21개 항목에 매핑"""
    kisa_items = load_kisa_items()
    mapping_rules = load_mapping_rules()

    mapping = {item["code"]: [] for item in kisa_items}

    for alert in alerts:
        alert_name = alert.get("alert", "")
        cwe_id = int(alert.get("cweid", "0") or "0")
        matched = False

        # 1차: 플레이북 매핑 규칙 (정확 매칭)
        for pattern, rule in mapping_rules.items():
            if pattern.lower() in alert_name.lower():
                mapping[rule["code"]].append(alert)
                matched = True
                break

        if matched:
            continue

        # 2차: CWE ID 매칭
        for item in kisa_items:
            if cwe_id in item.get("zap_cwe_ids", []):
                mapping[item["code"]].append(alert)
                matched = True
                break

        if matched:
            continue

        # 3차: 키워드 매칭
        for item in kisa_items:
            for pattern in item.get("zap_alert_patterns", []):
                if pattern.lower() in alert_name.lower():
                    mapping[item["code"]].append(alert)
                    matched = True
                    break
            if matched:
                break

    return mapping
