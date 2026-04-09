"""Gemma 4 AI 분석기 (Ollama 연동)"""

import json
import os
import time
import requests
from datetime import datetime

from scanner.logging_setup import logger, log_and_print
from scanner.config import BASE_DIR, OLLAMA_TIMEOUT
from scanner.retry import retry_with_backoff


def _load_prompt(name: str) -> tuple:
    """프롬프트 템플릿 로드 → (system, user) 튜플"""
    path = os.path.join(BASE_DIR, "prompts", f"{name}.txt")
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    parts = content.split("[USER]")
    system = parts[0].replace("[SYSTEM]", "").strip()
    user = parts[1].strip() if len(parts) > 1 else ""
    return system, user


class GemmaAnalyzer:
    """Ollama + Gemma 4 AI 분석"""

    def __init__(self, base_url: str, model: str):
        self.base_url = base_url.rstrip("/")
        self.model = model

    def check(self) -> bool:
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=10)
            models = [m["name"] for m in r.json().get("models", [])]
            if any("gemma4" in m for m in models):
                log_and_print(f"  [Ollama] 연결 성공 - {self.model}")
                return True
            log_and_print(f"  [Ollama] gemma4 미설치. 'ollama pull {self.model}' 실행 필요",
                          level="error")
            return False
        except Exception as e:
            log_and_print(f"  [Ollama] 연결 실패: {e}", level="error")
            return False

    def _chat(self, system: str, user: str, temp=0.3,
              show_progress=False, max_retries=2) -> str:
        last_error = None
        for attempt in range(max_retries + 1):
            try:
                return self._chat_stream(system, user, temp, show_progress)
            except requests.RequestException as e:
                last_error = e
                if attempt < max_retries:
                    import random
                    wait = min(5.0 * (2 ** attempt), 30.0) + random.uniform(0, 2)
                    logger.warning("[Ollama] 요청 실패 (%d/%d): %s - %.1f초 후 재시도",
                                   attempt + 1, max_retries, e, wait)
                    time.sleep(wait)
                else:
                    logger.error("AI 분석 최종 실패 (%d회 시도): %s",
                                 max_retries + 1, e)
        return f"AI 분석 실패: {last_error}"

    def _chat_stream(self, system: str, user: str, temp: float,
                     show_progress: bool) -> str:
        """Ollama 스트리밍 API 호출 (예외 발생 시 caller가 재시도)"""
        r = requests.post(f"{self.base_url}/api/chat", json={
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            "stream": True,
            "options": {"temperature": temp, "num_ctx": 8192}
        }, timeout=OLLAMA_TIMEOUT, stream=True)
        r.raise_for_status()
        content = ""
        token_count = 0
        start = time.time()
        for line in r.iter_lines():
            if not line:
                continue
            chunk = json.loads(line)
            token = chunk.get("message", {}).get("content", "")
            content += token
            token_count += 1
            if show_progress and token_count % 20 == 0:
                elapsed = int(time.time() - start)
                print(f"\r    생성 중... {token_count} 토큰 ({elapsed}초 경과)",
                      end="", flush=True)
            if chunk.get("done"):
                break
        if show_progress and token_count > 0:
            elapsed = int(time.time() - start)
            print(f"\r    완료: {token_count} 토큰 생성 ({elapsed}초 소요)        ")
            logger.info("[AI] 생성 완료: %d 토큰 (%d초 소요)", token_count, elapsed)
        return content

    def analyze_item(self, item: dict, zap_alerts: list,
                     manual_results=None) -> dict:
        """21개 항목별 AI 분석"""
        system_tmpl, user_tmpl = _load_prompt("item_analysis")

        alert_text = ""
        for a in zap_alerts[:8]:
            alert_text += (f"- {a.get('alert', '')}: {a.get('url', '')[:60]} "
                           f"(Risk:{a.get('risk', '')}, CWE:{a.get('cweid', '')})\n")

        manual_text = ""
        if manual_results:
            manual_text = (f"\n수동 점검 결과:\n"
                           f"{json.dumps(manual_results, ensure_ascii=False, indent=1)[:500]}")

        user = user_tmpl.format(
            code=item["code"],
            full_name=item["full_name"],
            importance=item["importance"],
            description=item["description"],
            zap_coverage=item["zap_coverage"],
            alert_count=len(zap_alerts),
            alert_text=alert_text if alert_text else "관련 경고 없음",
            manual_text=manual_text,
        )

        response = self._chat(system_tmpl, user)
        try:
            cleaned = response.strip()
            if "```" in cleaned:
                cleaned = (cleaned.split("```json")[1] if "```json" in cleaned
                           else cleaned.split("```")[1])
                cleaned = cleaned.split("```")[0]
            start = cleaned.find("{")
            end = cleaned.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(cleaned[start:end])
        except (json.JSONDecodeError, ValueError, IndexError) as e:
            logger.warning("[AI] JSON 파싱 실패 [%s]: %s", item.get("code", "?"), e)
        return {"verdict": "수동점검 필요", "scan_method_desc": "AI 분석",
                "detail": response[:400], "remediation": "수동 점검 필요"}

    def generate_summary(self, findings: list, target_url: str) -> str:
        """종합 의견 생성"""
        vuln = [f for f in findings if f.verdict == "취약"]
        warn = [f for f in findings if f.verdict == "주의"]
        safe = [f for f in findings if f.verdict == "양호"]
        manual = [f for f in findings if f.verdict == "수동점검 필요"]

        system_tmpl, user_tmpl = _load_prompt("summary")

        user = user_tmpl.format(
            target_url=target_url,
            scan_date=datetime.now().strftime('%Y-%m-%d'),
            vuln_count=len(vuln),
            warn_count=len(warn),
            safe_count=len(safe),
            manual_count=len(manual),
            vuln_items=', '.join(f'[{f.code}]{f.name}' for f in vuln) or '없음',
            warn_items=', '.join(f'[{f.code}]{f.name}' for f in warn) or '없음',
        )

        return self._chat(system_tmpl, user, temp=0.2, show_progress=True)
