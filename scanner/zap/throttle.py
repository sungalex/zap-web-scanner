"""ZAP 스캔 메모리/트래픽 제어"""

from scanner.logging_setup import logger, log_and_print


class ScanThrottle:
    """ZAP Active Scan 리소스 제어

    - 스레드 수 제한으로 메모리 사용량 감소
    - 요청 간 딜레이로 타겟 시스템 부하 제어
    """

    def __init__(self, zap_client):
        self.zap = zap_client

    def configure(self, threads_per_host: int = None, request_delay_ms: int = None,
                  max_scans_in_ui: int = None):
        """Active Scan 정책 설정

        Args:
            threads_per_host: 호스트당 스캔 스레드 수 (기본 ZAP: 2, 메모리 절약: 1)
            request_delay_ms: 요청 간 딜레이(ms) (타겟 부하 제어)
            max_scans_in_ui: UI에 표시할 최대 스캔 수
        """
        if threads_per_host is not None:
            r = self.zap._get("/JSON/ascan/action/setOptionThreadPerHost/",
                              {"Integer": str(threads_per_host)}, retries=1)
            if r:
                log_and_print(f"  [Throttle] 호스트당 스레드: {threads_per_host}")
            else:
                logger.warning("[Throttle] 스레드 수 설정 실패")

        if request_delay_ms is not None:
            r = self.zap._get("/JSON/ascan/action/setOptionDelayInMs/",
                              {"Integer": str(request_delay_ms)}, retries=1)
            if r:
                log_and_print(f"  [Throttle] 요청 딜레이: {request_delay_ms}ms")
            else:
                logger.warning("[Throttle] 딜레이 설정 실패")

        if max_scans_in_ui is not None:
            r = self.zap._get("/JSON/ascan/action/setOptionMaxScansInUI/",
                              {"Integer": str(max_scans_in_ui)}, retries=1)
            if r:
                logger.info("[Throttle] 최대 스캔 UI 표시: %d", max_scans_in_ui)

    def pause_scan(self, scan_id: str):
        """Active Scan 일시정지"""
        r = self.zap._get("/JSON/ascan/action/pause/", {"scanId": scan_id}, retries=1)
        if r:
            log_and_print(f"  [Throttle] 스캔 일시정지 (scanId: {scan_id})")

    def resume_scan(self, scan_id: str):
        """Active Scan 재개"""
        r = self.zap._get("/JSON/ascan/action/resume/", {"scanId": scan_id}, retries=1)
        if r:
            log_and_print(f"  [Throttle] 스캔 재개 (scanId: {scan_id})")
