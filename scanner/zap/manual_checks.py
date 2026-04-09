"""수동 점검 (HTTP 요청 기반)"""

import requests
from scanner.logging_setup import logger
from scanner.config import MANUAL_CHECK_TIMEOUT
from scanner.retry import retry_call


class ManualChecker:
    """ZAP이 커버하지 못하는 항목에 대한 HTTP 기반 수동 점검"""

    def __init__(self, kisa_items: list):
        self.kisa_items = {item["code"]: item for item in kisa_items}

    def _get_item_config(self, code: str) -> dict:
        item = self.kisa_items.get(code, {})
        return item.get("manual_check", {})

    def _http_get(self, url: str, allow_redirects=True, description=""):
        """재시도 포함 HTTP GET"""
        return retry_call(
            requests.get, url,
            timeout=MANUAL_CHECK_TIMEOUT, allow_redirects=allow_redirects, verify=False,
            max_retries=1, base_delay=2.0,
            exceptions=(requests.RequestException,),
            description=description,
            default=None,
        )

    def _http_method(self, method: str, url: str, description=""):
        """재시도 포함 HTTP 임의 메서드"""
        return retry_call(
            requests.request, method, url,
            timeout=MANUAL_CHECK_TIMEOUT, verify=False,
            max_retries=1, base_delay=2.0,
            exceptions=(requests.RequestException,),
            description=description,
            default=None,
        )

    def check_directories(self, base_url: str) -> list:
        """DI 점검: 디렉터리 인덱싱"""
        config = self._get_item_config("DI")
        paths = config.get("paths",
                           ["/_next/", "/_next/static/", "/images/", "/fonts/",
                            "/api/", "/uploads/", "/public/"])
        detect_patterns = config.get("detect_patterns",
                                     ["Index of", "Directory listing", "Parent Directory"])
        results = []
        for path in paths:
            r = self._http_get(f"{base_url.rstrip('/')}{path}",
                               description=f"DI {path}")
            if r:
                listing = any(p in r.text for p in detect_patterns)
                results.append({"path": path, "status": r.status_code, "listing": listing})
            else:
                results.append({"path": path, "status": "ERR", "listing": False})
        found = sum(1 for r in results if r.get("listing"))
        errs = sum(1 for r in results if r["status"] == "ERR")
        logger.info("[DI] 디렉터리 인덱싱 점검 완료: %d개 경로, 인덱싱 발견 %d건, 오류 %d건",
                    len(results), found, errs)
        return results

    def check_error_pages(self, base_url: str) -> list:
        """EP 점검: 에러 페이지"""
        config = self._get_item_config("EP")
        paths = config.get("paths",
                           ["/nonexistent-page-12345", "/../../etc/passwd",
                            "/%3Cscript%3Ealert(1)%3C/script%3E"])
        results = []
        for path in paths:
            r = self._http_get(f"{base_url.rstrip('/')}{path}",
                               description=f"EP {path}")
            if r:
                results.append({
                    "path": path, "status": r.status_code,
                    "stack_trace": any(p in r.text for p in
                                      ["Traceback", "Exception in", "Stack Trace",
                                       "at java.", "at org.", "at com.", "at net.",
                                       "in /var/", "in /home/", "in C:\\",
                                       "line \\d+", "Fatal error"]),
                    "server_info": any(p in r.text for p in
                                      ["nginx", "Apache", "Express", "node_modules"]),
                    "db_info": any(p in r.text for p in ["SQL", "mysql", "postgres"]),
                })
            else:
                results.append({"path": path, "status": "ERR"})
        issues = sum(1 for r in results if r.get("stack_trace") or r.get("server_info") or r.get("db_info"))
        logger.info("[EP] 에러 페이지 점검 완료: %d개 경로, 정보 노출 %d건", len(results), issues)
        return results

    def check_admin_pages(self, base_url: str) -> list:
        """AE 점검: 관리자 페이지 노출"""
        config = self._get_item_config("AE")
        paths = config.get("paths",
                           ["/admin", "/administrator", "/admin/login", "/manage",
                            "/manager", "/cms", "/wp-admin", "/dashboard",
                            "/console", "/backoffice", "/phpmyadmin"])
        results = []
        for path in paths:
            r = self._http_get(f"{base_url.rstrip('/')}{path}",
                               allow_redirects=False, description=f"AE {path}")
            if r:
                results.append({"path": path, "status": r.status_code})
            else:
                results.append({"path": path, "status": "ERR"})
        exposed = [r["path"] for r in results if r["status"] not in ("ERR", 404, 403)]
        logger.info("[AE] 관리자 페이지 점검 완료: %d개 경로, 접근 가능 %d건%s",
                    len(results), len(exposed),
                    f" ({', '.join(exposed)})" if exposed else "")
        return results

    def check_http_methods(self, base_url: str) -> list:
        """WM 점검: 불필요한 HTTP Method"""
        config = self._get_item_config("WM")
        methods = config.get("methods",
                             ["OPTIONS", "PUT", "DELETE", "PATCH", "HEAD", "TRACE"])
        results = []
        for method in methods:
            r = self._http_method(method, f"{base_url.rstrip('/')}/",
                                  description=f"WM {method}")
            if r:
                results.append({"method": method, "status": r.status_code})
            else:
                results.append({"method": method, "status": "ERR"})
        allowed = [r["method"] for r in results if r["status"] not in ("ERR", 405)]
        logger.info("[WM] HTTP Method 점검 완료: 허용된 메서드 %s",
                    ', '.join(allowed) if allowed else "없음")
        return results

    def check_security_headers(self, base_url: str) -> dict:
        """SN 점검: 보안 헤더"""
        r = self._http_get(f"{base_url.rstrip('/')}/", description="SN 보안 헤더")
        if not r:
            return {"https": False, "headers": {}}
        headers_to_check = [
            "strict-transport-security", "content-security-policy",
            "x-content-type-options", "x-frame-options",
            "referrer-policy", "permissions-policy"
        ]
        result = {"https": base_url.startswith("https"), "headers": {}}
        for h in headers_to_check:
            result["headers"][h] = r.headers.get(h, None)
        missing = [h for h in headers_to_check if not result["headers"][h]]
        logger.info("[SN] 보안 헤더 점검 완료: HTTPS=%s, 미설정 헤더 %d개%s",
                    result["https"], len(missing),
                    f" ({', '.join(missing)})" if missing else "")
        return result

    def check_cookies(self, base_url: str) -> dict:
        """CC 점검: 쿠키 보안 속성"""
        r = self._http_get(f"{base_url.rstrip('/')}/", description="CC 쿠키")
        if not r:
            return {"https": False, "cookie_count": 0, "cookies": []}
        cookies = []
        for cookie_header in r.headers.get("set-cookie", "").split(","):
            if not cookie_header.strip():
                continue
            lower = cookie_header.lower()
            cookies.append({
                "raw": cookie_header.strip()[:200],
                "httponly": "httponly" in lower,
                "secure": "secure" in lower,
                "samesite": "samesite" in lower,
            })
        result = {
            "https": base_url.startswith("https"),
            "cookie_count": len(cookies),
            "cookies": cookies,
        }
        insecure = sum(1 for c in cookies if not c["httponly"] or not c["secure"])
        logger.info("[CC] 쿠키 점검 완료: %d개 쿠키, 보안 속성 미흡 %d건",
                    len(cookies), insecure)
        return result

    def run_all(self, base_url: str) -> dict:
        """모든 수동 점검 실행"""
        return {
            "DI": self.check_directories(base_url),
            "EP": self.check_error_pages(base_url),
            "AE": self.check_admin_pages(base_url),
            "WM": self.check_http_methods(base_url),
            "SN": self.check_security_headers(base_url),
            "CC": self.check_cookies(base_url),
        }
