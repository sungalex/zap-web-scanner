"""스캔 오케스트레이터 — 8단계 워크플로"""

import os
import re
import json
import time
from datetime import datetime

from scanner.config import ScanConfig, load_kisa_items, BASE_DIR
from scanner.models import Finding, ScanCheckpoint
from scanner.logging_setup import logger, log_and_print, setup_file_handler
from scanner.zap.client import ZAPClient
from scanner.zap.manual_checks import ManualChecker
from scanner.zap.throttle import ScanThrottle
from scanner.analysis.analyzer import GemmaAnalyzer
from scanner.analysis.mapper import map_alerts_to_items
from scanner.report.json_report import generate_json_report
from scanner.report.docx_report import generate_docx_report


class ScanOrchestrator:
    """8단계 스캔 워크플로 관리"""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.start_time = time.time()

        # 출력 폴더
        os.makedirs("logs", exist_ok=True)
        os.makedirs("docs", exist_ok=True)
        self.zap_log_dir = os.path.join("logs", "zap")
        os.makedirs(self.zap_log_dir, exist_ok=True)

        # 로깅
        self.log_path = os.path.join("logs", f"scan_{self.timestamp}.log")
        setup_file_handler(self.log_path)

        # 타임아웃 오버라이드 적용
        if config.passive_timeout is not None:
            import scanner.config as cfg
            cfg.PASSIVE_SCAN_TIMEOUT = config.passive_timeout
        if config.ollama_timeout is not None:
            import scanner.config as cfg
            cfg.OLLAMA_TIMEOUT = config.ollama_timeout

        # 컴포넌트
        self.zap = ZAPClient(config.zap_url, config.zap_key)
        self.throttle = ScanThrottle(self.zap)
        self.gemma = GemmaAnalyzer(config.ollama_url, config.ollama_model)
        self.manual_checker = ManualChecker(load_kisa_items())

        # 상태
        self.context_id = ""
        self.context_name = f"WebScan-{self.timestamp}"
        self.urls = []
        self.all_alerts = []
        self.summary = {}
        self.manual_results = {}
        self.findings = []
        self.exec_summary = ""

        # 체크포인트
        self.checkpoint = ScanCheckpoint(
            scan_id=self.timestamp,
            target_url=config.target_url,
            config={
                "zap_url": config.zap_url, "ollama_url": config.ollama_url,
                "ollama_model": config.ollama_model, "skip_active": config.skip_active,
            },
        )

    def run(self, resume_checkpoint: ScanCheckpoint = None):
        """전체 스캔 실행 (resume_checkpoint 전달 시 중단점부터 재개)"""
        target = self.config.target_url

        if resume_checkpoint:
            self.checkpoint = resume_checkpoint
            self._restore_from_checkpoint()
            logger.info("스캔 재개 - 대상: %s (완료 단계: %s)",
                        target, self.checkpoint.completed_stages)
            print("=" * 64)
            print("  스캔 재개 (중단점 복구)")
            print(f"  완료 단계: {self.checkpoint.completed_stages}")
            print(f"  대상: {target}")
            print("=" * 64)
        else:
            logger.info("스캔 시작 - 대상: %s", target)
            print("=" * 64)
            print("  주요정보통신기반시설 웹 취약점 자동 진단 시스템 v2.0")
            print(f"  기준: 2026 가이드 - Web Application(웹) 21개 항목")
            print(f"  대상: {target}")
            print(f"  시작: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("=" * 64)

        completed = self.checkpoint.completed_stages

        if 1 not in completed:
            if not self.stage_1_connect():
                return None
            self.checkpoint.mark_stage(1)
            self.checkpoint.save()
        else:
            # 재개 시에도 연결 확인은 필수
            if not self.stage_1_connect():
                return None

        if 3 not in completed:
            self.stage_3_context()
            self.checkpoint.mark_stage(3, {"context_id": self.context_id,
                                           "context_name": self.context_name})
            self.checkpoint.save()

        if 4 not in completed:
            self.stage_4_spider()
            self.checkpoint.mark_stage(4, {"url_count": len(self.urls)})
            self.checkpoint.save()

        if 5 not in completed:
            self.stage_5_scan()
            self.checkpoint.mark_stage(5)
            self.checkpoint.save()

        if 6 not in completed:
            self.stage_6_collect()
            self.checkpoint.mark_stage(6, {"alert_count": len(self.all_alerts)})
            self.checkpoint.save()

        if 7 not in completed:
            self.stage_7_manual()
            self.checkpoint.mark_stage(7)
            self.checkpoint.save()

        # 8단계는 항목별 부분 재실행 지원
        self.stage_8_analyze()
        self.checkpoint.mark_stage(8)
        self.checkpoint.save()

        return self._finalize()

    def _restore_from_checkpoint(self):
        """체크포인트에서 상태 복원"""
        sd = self.checkpoint.stage_data
        if "3" in sd:
            self.context_id = sd["3"].get("context_id", "")
            self.context_name = sd["3"].get("context_name", self.context_name)
        # 4~7단계 데이터는 logs/zap/ 파일에서 복원
        scan_id = self.checkpoint.scan_id
        zap_dir = self.zap_log_dir

        urls_path = os.path.join(zap_dir, f"spider_urls_{scan_id}.json")
        if os.path.exists(urls_path):
            with open(urls_path, "r", encoding="utf-8") as f:
                self.urls = json.load(f)

        alerts_path = os.path.join(zap_dir, f"alerts_raw_{scan_id}.json")
        if os.path.exists(alerts_path):
            with open(alerts_path, "r", encoding="utf-8") as f:
                self.all_alerts = json.load(f)

        summary_path = os.path.join(zap_dir, f"alerts_summary_{scan_id}.json")
        if os.path.exists(summary_path):
            with open(summary_path, "r", encoding="utf-8") as f:
                self.summary = json.load(f)

        manual_path = os.path.join(zap_dir, f"manual_checks_{scan_id}.json")
        if os.path.exists(manual_path):
            with open(manual_path, "r", encoding="utf-8") as f:
                self.manual_results = json.load(f)

        # 분석 완료된 항목 복원
        findings_path = os.path.join(zap_dir, f"findings_{scan_id}.json")
        if os.path.exists(findings_path):
            with open(findings_path, "r", encoding="utf-8") as f:
                for fd in json.load(f):
                    self.findings.append(Finding.from_dict(fd))

    # ── 1단계: 연결 확인 ──

    def stage_1_connect(self) -> bool:
        stage_start = time.time()
        log_and_print("\n[1단계] 연결 확인")
        if not self.zap.check():
            logger.error("[1단계] 실패 (%.1f초) - ZAP 연결 불가", time.time() - stage_start)
            print("\n  ZAP 실행 필요:")
            print("  docker run -u zap -p 8080:8080 zaproxy/zap-stable zap.sh "
                  "-daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true")
            return False
        if not self.gemma.check():
            logger.error("[1단계] 실패 (%.1f초) - Ollama 연결 불가", time.time() - stage_start)
            print(f"\n  Ollama 실행 필요: ollama pull {self.config.ollama_model} && ollama serve")
            return False
        log_and_print(f"  [1단계] 완료 ({time.time() - stage_start:.1f}초) - ZAP, Ollama 연결 성공")
        return True

    # ── 3단계: 컨텍스트 & 인증 ──

    def stage_3_context(self):
        stage_start = time.time()
        log_and_print("\n[3단계] 컨텍스트 설정")
        target = self.config.target_url

        self.context_id = self.zap.create_context(self.context_name)
        regex = re.sub(r'(https?://)', r'\1', target).replace('.', '\\.') + ".*"
        self.zap.include_in_context(self.context_name, regex)

        auth = self.config.auth_config
        if auth:
            logger.info("[3단계] 인증 설정")
            print("  [인증] 설정 중...")
            if auth.get("api_backend"):
                backend_regex = auth["api_backend"].replace('.', '\\.').replace(':', '\\:') + ".*"
                self.zap.include_in_context(self.context_name, backend_regex)
            self.zap.setup_auth(self.context_id, auth["login_url"], auth["login_data"],
                                auth.get("auth_type", "jsonBasedAuthentication"))
            self.zap.set_indicators(self.context_id,
                                    auth.get("logged_in", "\\Qlogout\\E"),
                                    auth.get("logged_out", "\\Qlogin\\E"))
            self.zap.create_user(self.context_id, auth["username"], auth["password"])

        auth_status = "설정" if auth else "미설정"
        log_and_print(f"  [3단계] 완료 ({time.time() - stage_start:.1f}초) - 컨텍스트 ID:{self.context_id}, 인증: {auth_status}")

    # ── 4단계: Spider ──

    def stage_4_spider(self):
        stage_start = time.time()
        log_and_print("\n[4단계] Spider 크롤링")
        self.urls = self.zap.spider(self.config.target_url, self.context_name)
        log_and_print(f"  [4단계] 완료 ({time.time() - stage_start:.1f}초) - {len(self.urls)}개 URL 발견")

        self._save_zap_data("spider_urls", self.urls)

    # ── 5단계: Passive + Active Scan ──

    def stage_5_scan(self):
        stage_start = time.time()
        log_and_print("\n[5단계] Passive Scan + Active Scan")
        passive_ok = self.zap.wait_passive()

        if not self.config.skip_active:
            # 스캔 리소스 제어 적용
            if self.config.scan_threads or self.config.request_delay:
                self.throttle.configure(
                    threads_per_host=self.config.scan_threads,
                    request_delay_ms=self.config.request_delay,
                )
            self.zap.active_scan(self.config.target_url, context_id=self.context_id)
            self.zap.wait_passive()
            active_status = "Active 완료"
        else:
            log_and_print("  [Active Scan] 건너뜀 (--skip-active)")
            active_status = "Active 건너뜀"

        passive_status = "Passive 완료" if passive_ok else "Passive 타임아웃"
        log_and_print(f"  [5단계] 완료 ({time.time() - stage_start:.1f}초) - {passive_status}, {active_status}")

    # ── 6단계: 결과 수집 ──

    def stage_6_collect(self):
        stage_start = time.time()
        log_and_print("\n[6단계] ZAP 결과 수집")
        target = self.config.target_url

        self.all_alerts = self.zap.get_alerts(target)
        log_and_print(f"  총 ZAP 경고: {len(self.all_alerts)}건")

        self.summary = self.zap.get_alerts_summary(target)
        for k, v in (self.summary or {}).items():
            print(f"    {k}: {v}")

        log_and_print(f"  [6단계] 완료 ({time.time() - stage_start:.1f}초) - {len(self.all_alerts)}건 경고 수집")

        self._save_zap_data("alerts_raw", self.all_alerts)
        self._save_zap_data("alerts_summary", self.summary or {})

    # ── 7단계: 수동 점검 ──

    def stage_7_manual(self):
        stage_start = time.time()
        log_and_print("\n[7단계] 수동 점검")
        target = self.config.target_url

        checks = [
            ("DI", "디렉터리 인덱싱", self.manual_checker.check_directories),
            ("EP", "에러 페이지", self.manual_checker.check_error_pages),
            ("AE", "관리자 페이지 노출", self.manual_checker.check_admin_pages),
            ("WM", "HTTP Method", self.manual_checker.check_http_methods),
            ("SN", "보안 헤더", self.manual_checker.check_security_headers),
            ("CC", "쿠키 보안 속성", self.manual_checker.check_cookies),
        ]

        for code, name, check_fn in checks:
            print(f"  [{code}] {name} 점검...")
            self.manual_results[code] = check_fn(target)
            result = self.manual_results[code]
            count = len(result) if isinstance(result, list) else ""
            count_str = f" ({count}건)" if count != "" else ""
            logger.info("[7단계] %s 점검 완료%s", code, count_str)

        log_and_print(f"  [7단계] 완료 ({time.time() - stage_start:.1f}초) - 6개 항목 수동 점검")

        self._save_zap_data("manual_checks", self.manual_results)
        logger.info("ZAP 결과 저장: %s", self.zap_log_dir)

    # ── 8단계: AI 분석 & 보고서 ──

    def stage_8_analyze(self):
        stage_start = time.time()
        log_and_print("\n[8단계] AI 분석 및 보고서 생성")

        alert_mapping = map_alerts_to_items(self.all_alerts)
        kisa_items = load_kisa_items()

        # 이미 분석된 항목 코드 목록 (resume 시 건너뛰기용)
        analyzed_codes = {f.code for f in self.findings}
        if analyzed_codes:
            logger.info("[8단계] 이전 분석 결과 복원: %d개 항목 (%s)",
                        len(analyzed_codes), ", ".join(sorted(analyzed_codes)))

        for item in kisa_items:
            code = item["code"]

            # 이미 분석된 항목은 건너뛰기
            if code in analyzed_codes:
                print(f"  [{code}] {item['name']} → 이전 결과 사용")
                continue

            mapped_alerts = alert_mapping.get(code, [])
            mr = self.manual_results.get(code)
            print(f"  [{code}] {item['name']} (경고:{len(mapped_alerts)}건)...",
                  end=" ")

            ai = self.gemma.analyze_item(item, mapped_alerts, mr)

            self.findings.append(Finding(
                code=code,
                name=item["name"],
                full_name=item["full_name"],
                importance=item["importance"],
                verdict=ai.get("verdict", "수동점검 필요"),
                scan_method_desc=ai.get("scan_method_desc", ""),
                detail=ai.get("detail", ""),
                remediation=ai.get("remediation", ""),
                zap_alerts=mapped_alerts,
            ))
            logger.info("[%s] %s → %s (경고:%d건)",
                        code, item['name'], self.findings[-1].verdict,
                        len(mapped_alerts))
            print(f"→ {self.findings[-1].verdict}")

            # 항목별 중간 저장 (실패 시 여기서부터 재개 가능)
            self.checkpoint.analyzed_items.append(code)
            self._save_zap_data("findings", [f.to_dict() for f in self.findings])
            self.checkpoint.save()

        # 종합 요약
        logger.info("종합 의견 생성 시작")
        print("\n  [종합 의견 생성 중...]")
        self.exec_summary = self.gemma.generate_summary(
            self.findings, self.config.target_url)
        if self.exec_summary.startswith("AI 분석 실패"):
            logger.error("종합 의견 생성 실패: %s", self.exec_summary)
        else:
            logger.info("종합 의견 생성 완료 (%d자)", len(self.exec_summary))

        v = sum(1 for f in self.findings if f.verdict == "취약")
        w = sum(1 for f in self.findings if f.verdict == "주의")
        s = sum(1 for f in self.findings if f.verdict == "양호")
        m = sum(1 for f in self.findings if f.verdict == "수동점검 필요")
        log_and_print(
            f"  [8단계] 완료 ({time.time() - stage_start:.1f}초) - "
            f"{len(self.findings)}개 항목 분석 (취약:{v}, 주의:{w}, 양호:{s}, 수동점검:{m})")

    # ── 결과 출력 및 보고서 저장 ──

    def _finalize(self):
        elapsed = time.time() - self.start_time
        scan_meta = {"duration": f"{int(elapsed // 60)}분 {int(elapsed % 60)}초"}

        # JSON 저장
        json_path = os.path.join("docs", f"vuln_report_{self.timestamp}.json")
        json_data = generate_json_report(
            self.findings, self.config.target_url, self.exec_summary,
            scan_meta, self.config.ollama_model)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, ensure_ascii=False, indent=2)
        logger.info("JSON 보고서 저장: %s", json_path)

        # DOCX 저장
        docx_path = os.path.join("docs", f"vuln_report_{self.timestamp}.docx")
        print(f"\n  DOCX 생성 중...")
        try:
            generate_docx_report(
                self.findings, self.config.target_url, self.exec_summary,
                scan_meta, os.path.abspath(docx_path))
            logger.info("DOCX 생성 완료: %s", docx_path)
            print(f"  DOCX 생성 완료: {docx_path}")
        except Exception as e:
            logger.error("DOCX 생성 실패: %s", e)
            print(f"  DOCX 생성 실패: {e}")

        # 결과 출력
        v = sum(1 for f in self.findings if f.verdict == "취약")
        w = sum(1 for f in self.findings if f.verdict == "주의")
        s = sum(1 for f in self.findings if f.verdict == "양호")
        m = sum(1 for f in self.findings if f.verdict == "수동점검 필요")

        # 로그: 핵심 결과 요약
        logger.info("진단 완료 - 취약: %d | 주의: %d | 양호: %d | 수동점검: %d | 소요시간: %s",
                     v, w, s, m, scan_meta['duration'])
        logger.info("보고서: JSON=%s, DOCX=%s", json_path, docx_path)
        logger.info("ZAP 원시 데이터: %s", self.zap_log_dir)

        # 콘솔: 시각적 결과 배너
        print("\n" + "=" * 64)
        print("  진단 완료")
        print("=" * 64)
        print(f"  점검 항목: 21개 | 취약: {v} | 주의: {w} | 양호: {s} | 수동점검: {m}")
        print(f"  소요시간: {scan_meta['duration']}")
        print(f"  DOCX: {docx_path}")
        print(f"  JSON: {json_path}")
        print(f"  LOG:  {self.log_path}")
        print(f"  ZAP:  {self.zap_log_dir}")

        return docx_path, json_path

    # ── 유틸리티 ──

    def _save_zap_data(self, name: str, data):
        """ZAP 결과를 logs/zap/ 에 JSON으로 저장"""
        try:
            path = os.path.join(self.zap_log_dir, f"{name}_{self.timestamp}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error("%s 저장 실패: %s", name, e)
