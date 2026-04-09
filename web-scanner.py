#!/usr/bin/env python3
"""
주요정보통신기반시설 웹 취약점 자동 진단 시스템
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- 진단 기준: 2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 - Web Application(웹) 21개 항목
- 스캔 도구: OWASP ZAP 2.17.0 (REST API)
- AI 분석:  Ollama + Gemma 4 (로컬)
- 보고서:   DOCX (가이드 양식) + JSON (기계판독)
- 워크플로: ZAP MCP 플레이북 8단계 기반
"""

import argparse
import os
from dotenv import load_dotenv

load_dotenv()

from scanner.config import ScanConfig
from scanner.models import ScanCheckpoint
from scanner.orchestrator import ScanOrchestrator


def _run_check(zap_url, zap_key, ollama_url, model):
    """환경 검증: 스캔 없이 연결 상태만 확인"""
    from scanner.zap.client import ZAPClient
    from scanner.analysis.analyzer import GemmaAnalyzer

    print("\n[환경 검증]")
    ok = True

    zap = ZAPClient(zap_url, zap_key)
    if not zap.check():
        ok = False

    gemma = GemmaAnalyzer(ollama_url, model)
    if not gemma.check():
        ok = False

    # Python 의존성
    try:
        import requests, dotenv, docx
        print("  [Python] 의존성 확인 (requests, python-dotenv, python-docx)  OK")
    except ImportError as e:
        print(f"  [Python] 의존성 누락: {e}")
        ok = False

    # 출력 디렉터리
    for d in ["logs", "docs"]:
        os.makedirs(d, exist_ok=True)
        test_path = os.path.join(d, ".write_test")
        try:
            with open(test_path, "w") as f:
                f.write("test")
            os.unlink(test_path)
        except OSError:
            print(f"  [출력] {d}/ 디렉터리 쓰기 불가")
            ok = False
    if ok:
        print("  [출력] 디렉터리 쓰기 가능 (logs/, docs/)  OK")

    print()
    if ok:
        print("  환경 검증 완료 - 모든 항목 정상")
    else:
        print("  환경 검증 실패 - 위 오류를 확인하세요")


def main():
    parser = argparse.ArgumentParser(
        description="주요정보통신기반시설 웹 취약점 자동 진단 v2.0 (2026 가이드 21개 항목)")
    parser.add_argument("target", nargs="?", help="진단 대상 URL")
    parser.add_argument("--skip-active", action="store_true")
    parser.add_argument("--resume", help="체크포인트에서 재개 (scan_id 또는 파일 경로)")
    parser.add_argument("--check", action="store_true", help="환경 검증만 실행 (스캔 없음)")
    parser.add_argument("--zap-url",
                        default=os.getenv("ZAP_API_URL", "http://localhost:8090"))
    parser.add_argument("--zap-key",
                        default=os.getenv("ZAP_API_KEY", ""))
    parser.add_argument("--ollama-url",
                        default=os.getenv("OLLAMA_URL", "http://localhost:11434"))
    parser.add_argument("--model",
                        default=os.getenv("OLLAMA_MODEL", "gemma4:e4b"))
    # 인증 옵션
    parser.add_argument("--login-url", help="로그인 API URL")
    parser.add_argument("--login-data",
                        help='로그인 JSON (예: {"email":"{%%username%%}","password":"{%%password%%}"})')
    parser.add_argument("--username", help="로그인 ID")
    parser.add_argument("--password", help="로그인 PW")
    parser.add_argument("--logged-in", default="\\Qlogout\\E|\\Q로그아웃\\E")
    parser.add_argument("--logged-out", default="\\Qlogin\\E|\\Q로그인\\E")
    parser.add_argument("--api-backend", help="API 백엔드 도메인 (프론트와 다를 때)")
    # 스캔 제어
    parser.add_argument("--scan-threads", type=int, help="호스트당 스캔 스레드 수 (기본: ZAP 기본값, 메모리 절약: 1)")
    parser.add_argument("--request-delay", type=int, help="ZAP 요청 간 딜레이(ms, 타겟 부하 제어)")
    # 타임아웃
    parser.add_argument("--passive-timeout", type=int, help="Passive Scan 타임아웃(초, 기본: 120)")
    parser.add_argument("--ollama-timeout", type=int, help="Ollama AI 타임아웃(초, 기본: 900)")

    args = parser.parse_args()

    # --check 모드: 환경 검증
    if args.check:
        _run_check(args.zap_url, args.zap_key, args.ollama_url, args.model)
        return

    # --resume 모드
    if args.resume:
        resume_path = args.resume
        if not os.path.exists(resume_path):
            resume_path = os.path.join("logs", f"checkpoint_{args.resume}.json")
        if not os.path.exists(resume_path):
            print(f"  체크포인트 파일을 찾을 수 없습니다: {args.resume}")
            return

        checkpoint = ScanCheckpoint.load(resume_path)
        config = ScanConfig(
            target_url=checkpoint.target_url,
            zap_url=args.zap_url,
            zap_key=args.zap_key,
            ollama_url=args.ollama_url,
            ollama_model=args.model,
            skip_active=checkpoint.config.get("skip_active", False),
            scan_threads=args.scan_threads,
            request_delay=args.request_delay,
            passive_timeout=args.passive_timeout,
            ollama_timeout=args.ollama_timeout,
        )
        orchestrator = ScanOrchestrator(config)
        orchestrator.run(resume_checkpoint=checkpoint)
        return

    # 일반 모드
    if not args.target:
        parser.error("target URL이 필요합니다 (--resume 사용 시 제외)")

    auth = None
    if args.login_url and args.username:
        auth = {
            "login_url": args.login_url,
            "login_data": args.login_data or
                f'{{"email":"{{%username%}}","password":"{{%password%}}"}}',
            "username": args.username,
            "password": args.password,
            "logged_in": args.logged_in,
            "logged_out": args.logged_out,
            "api_backend": args.api_backend,
        }

    config = ScanConfig(
        target_url=args.target,
        zap_url=args.zap_url,
        zap_key=args.zap_key,
        ollama_url=args.ollama_url,
        ollama_model=args.model,
        skip_active=args.skip_active,
        auth_config=auth,
        scan_threads=args.scan_threads,
        request_delay=args.request_delay,
        passive_timeout=args.passive_timeout,
        ollama_timeout=args.ollama_timeout,
    )

    orchestrator = ScanOrchestrator(config)
    orchestrator.run()


if __name__ == "__main__":
    main()
