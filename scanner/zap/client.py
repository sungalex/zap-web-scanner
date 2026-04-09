"""ZAP REST API 클라이언트"""

import time
import requests
from urllib.parse import quote

from scanner.logging_setup import logger, log_and_print
from scanner.retry import retry_call
from scanner.config import (
    ZAP_REQUEST_TIMEOUT, PASSIVE_SCAN_TIMEOUT, PASSIVE_SCAN_MAX_RETRIES,
    SPIDER_POLL_INTERVAL, AJAX_SPIDER_POLL_INTERVAL,
    PASSIVE_SCAN_POLL_INTERVAL, ACTIVE_SCAN_POLL_INTERVAL,
)


class ZAPClient:
    """OWASP ZAP REST API 래퍼"""

    def __init__(self, base_url: str, api_key: str = ""):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _get(self, path, params=None, retries=2):
        """ZAP API GET 요청 (재시도 포함)"""
        params = params or {}
        if self.api_key:
            params["apikey"] = self.api_key

        def _do_request():
            r = requests.get(f"{self.base_url}{path}", params=params,
                             timeout=ZAP_REQUEST_TIMEOUT)
            r.raise_for_status()
            return r.json()

        result = retry_call(
            _do_request,
            max_retries=retries,
            base_delay=2.0,
            exceptions=(requests.RequestException, ValueError),
            description=f"ZAP {path}",
            default=None,
        )
        return result

    # ── 연결 확인 ──

    def check(self) -> bool:
        result = self._get("/JSON/core/view/version/")
        if result:
            log_and_print(f"  [ZAP] 연결 성공 - v{result.get('version', '?')}")
            return True
        logger.error("[ZAP] 연결 실패")
        return False

    # ── 컨텍스트 & 인증 ──

    def create_context(self, name: str) -> str:
        r = self._get("/JSON/context/action/newContext/", {"contextName": name})
        cid = r.get("contextId", "") if r else ""
        log_and_print(f"  [Context] 생성: {name} (ID: {cid})")
        return cid

    def include_in_context(self, name: str, regex: str):
        self._get("/JSON/context/action/includeInContext/",
                  {"contextName": name, "regex": regex})

    def setup_auth(self, context_id: str, login_url: str, login_data: str,
                   auth_type: str = "jsonBasedAuthentication"):
        encoded_url = quote(login_url, safe='')
        encoded_data = quote(login_data, safe='')
        params = f"loginUrl={encoded_url}&loginRequestData={encoded_data}"
        self._get("/JSON/authentication/action/setAuthenticationMethod/",
                  {"contextId": context_id, "authMethodName": auth_type,
                   "authMethodConfigParams": params})

    def set_indicators(self, context_id: str, logged_in: str, logged_out: str):
        self._get("/JSON/authentication/action/setLoggedInIndicator/",
                  {"contextId": context_id, "loggedInIndicatorRegex": logged_in})
        self._get("/JSON/authentication/action/setLoggedOutIndicator/",
                  {"contextId": context_id, "loggedOutIndicatorRegex": logged_out})

    def create_user(self, context_id: str, username: str, password: str) -> str:
        r = self._get("/JSON/users/action/newUser/",
                      {"contextId": context_id, "name": "tester"})
        uid = r.get("userId", "") if r else ""
        if uid:
            encoded_user = quote(username, safe='')
            encoded_pass = quote(password, safe='')
            self._get("/JSON/users/action/setAuthenticationCredentials/",
                      {"contextId": context_id, "userId": uid,
                       "authCredentialsConfigParams":
                           f"username={encoded_user}&password={encoded_pass}"})
            self._get("/JSON/users/action/setUserEnabled/",
                      {"contextId": context_id, "userId": uid, "enabled": "true"})
            self._get("/JSON/forcedUser/action/setForcedUser/",
                      {"contextId": context_id, "userId": uid})
            self._get("/JSON/forcedUser/action/setForcedUserModeEnabled/",
                      {"enabled": "true"})
        return uid

    # ── Spider ──

    def spider(self, url: str, context_name: str = "") -> list:
        log_and_print(f"\n  [Spider] 크롤링 시작: {url}")
        params = {"url": url, "recurse": "true", "subtreeOnly": "true"}
        if context_name:
            params["contextName"] = context_name
        r = self._get("/JSON/spider/action/scan/", params)
        if not r:
            return []
        sid = r.get("scan", "0")
        last_logged = -1
        while True:
            s = self._get("/JSON/spider/view/status/", {"scanId": sid})
            if not s:
                break
            p = int(s.get("status", "100"))
            print(f"\r  [Spider] {p}%", end="", flush=True)
            if p >= 100:
                break
            if p >= last_logged + 25:
                logger.info("[Spider] 진행률: %d%%", p)
                last_logged = p
            time.sleep(SPIDER_POLL_INTERVAL)
        print()
        urls_r = self._get("/JSON/spider/view/results/", {"scanId": sid})
        urls = urls_r.get("results", []) if urls_r else []
        log_and_print(f"  [Spider] 발견 URL: {len(urls)}개")
        return urls

    def ajax_spider(self, url: str, context_name: str = ""):
        log_and_print(f"  [Ajax Spider] 시작: {url}")
        params = {"url": url, "subtreeOnly": "true"}
        if context_name:
            params["contextName"] = context_name
        self._get("/JSON/ajaxSpider/action/scan/", params)
        while True:
            s = self._get("/JSON/ajaxSpider/view/status/")
            if not s or s.get("status", "stopped") == "stopped":
                break
            time.sleep(AJAX_SPIDER_POLL_INTERVAL)
        log_and_print("  [Ajax Spider] 완료")

    # ── Passive / Active Scan ──

    def wait_passive(self, timeout=PASSIVE_SCAN_TIMEOUT,
                     max_retries=PASSIVE_SCAN_MAX_RETRIES):
        for attempt in range(1, max_retries + 1):
            start = time.time()
            remaining = -1
            while time.time() - start < timeout:
                r = self._get("/JSON/pscan/view/recordsToScan/")
                remaining = int(r.get("recordsToScan", "0")) if r else -1
                if remaining == 0:
                    log_and_print("  [Passive Scan] 완료")
                    return True
                time.sleep(PASSIVE_SCAN_POLL_INTERVAL)
            if attempt < max_retries:
                log_and_print(
                    f"  [Passive Scan] 타임아웃 (잔여 {remaining}건) - 재시도 {attempt}/{max_retries}",
                    level="warning")
            else:
                log_and_print(
                    f"  [Passive Scan] 타임아웃 (잔여 {remaining}건) - 최대 재시도 초과, 계속 진행",
                    level="warning")
        return False

    def active_scan(self, url: str, context_id: str = "") -> str:
        log_and_print(f"\n  [Active Scan] 시작: {url}")
        params = {"url": url, "recurse": "true", "subtreeOnly": "true"}
        if context_id:
            params["contextId"] = context_id
        r = self._get("/JSON/ascan/action/scan/", params)
        if not r:
            return ""
        sid = r.get("scan", "0")
        last_logged = -1
        while True:
            s = self._get("/JSON/ascan/view/status/", {"scanId": sid})
            if not s:
                break
            p = int(s.get("status", "100"))
            print(f"\r  [Active Scan] {p}%", end="", flush=True)
            if p >= 100:
                break
            if p >= last_logged + 10:
                logger.info("[Active Scan] 진행률: %d%%", p)
                last_logged = p
            time.sleep(ACTIVE_SCAN_POLL_INTERVAL)
        print()
        log_and_print(f"  [Active Scan] 완료 (scanId: {sid})")
        return sid

    # ── 결과 수집 ──

    def get_alerts(self, base_url: str = "", risk_id: str = "") -> list:
        params = {"start": "0", "count": "500"}
        if base_url:
            params["baseurl"] = base_url
        if risk_id:
            params["riskId"] = risk_id
        r = self._get("/JSON/alert/view/alerts/", params)
        return r.get("alerts", []) if r else []

    def get_alerts_summary(self, base_url: str) -> dict:
        r = self._get("/JSON/alert/view/alertsSummary/", {"baseurl": base_url})
        return r.get("alertsSummary", {}) if r else {}
