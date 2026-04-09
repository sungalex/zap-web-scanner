"""JSON 보고서 생성"""

from datetime import datetime


def generate_json_report(findings: list, target_url: str,
                         summary: str, scan_meta: dict,
                         ollama_model: str = "") -> dict:
    return {
        "report_title": "웹 애플리케이션 취약점 분석·평가 보고서",
        "standard": "2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 - Web Application(웹) 21개 항목",
        "target": target_url,
        "scan_date": datetime.now().isoformat(),
        "scan_tools": f"OWASP ZAP + Ollama {ollama_model}",
        "duration": scan_meta.get("duration", ""),
        "verdict_summary": {
            "취약": sum(1 for f in findings if f.verdict == "취약"),
            "주의": sum(1 for f in findings if f.verdict == "주의"),
            "양호": sum(1 for f in findings if f.verdict == "양호"),
            "수동점검 필요": sum(1 for f in findings if f.verdict == "수동점검 필요"),
            "합계": len(findings),
        },
        "findings": [
            {
                "code": f.code, "name": f.name, "full_name": f.full_name,
                "importance": f.importance, "verdict": f.verdict,
                "scan_method": f.scan_method_desc, "detail": f.detail,
                "remediation": f.remediation, "alert_count": len(f.zap_alerts),
            }
            for f in findings
        ],
        "summary": summary,
    }
