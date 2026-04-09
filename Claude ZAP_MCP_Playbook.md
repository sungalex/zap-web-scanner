# ZAP MCP 인증 스캔 플레이북
(주요정보통신기반시설 기술적 취약점 분석·평가 가이드 통합)

> **용도**: 이 문서를 Claude에게 첨부하면, ZAP MCP로 웹 취약점을 점검하고
> **주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 — Web Application(웹) 21개 항목** 기준의 보고서를 작성합니다.
> **버전**: 2.0 (2026-04-08)
> **기반**: OWASP ZAP 2.17.0 + Chrome 브라우저 수동 점검 + 실전 수행 경험

---

## 📌 사전 준비 (사용자 → Claude 제공 정보)

아래 정보를 Claude에게 **첫 메시지에 모두 포함**하면 토큰 사용을 최소화할 수 있습니다.

```
## 점검 요청
- 점검 대상 URL: https://example.com
- 로그인 페이지 URL: https://example.com/login (인증 점검 시)
- 로그인 API: https://example.com/api/auth/login (알면 제공, 모르면 "확인 필요")
- 인증 방식: [json / form / http] (모르면 "확인 필요")
- 로그인 요청 JSON 예시: {"email":"{이메일}","password":"{비밀번호}"} (알면 제공)
- ID/PW: user@example.com / password123
- 로그인 성공 지시자: "마이페이지" 또는 "로그아웃" (로그인 후 화면에 보이는 텍스트)
- 로그아웃 지시자: "로그인" 또는 "로그인/회원가입" (비로그인 시 화면 텍스트)
- API 백엔드 도메인: https://api.example.com (프론트와 다른 경우)
- 점검 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 가이드 (웹 21개 항목)
- 환경: [운영 / 테스트] (운영일 경우 부하 제한 필요)
- 주의사항: (방화벽 차단 가능, 특정 시간대 제한 등)
```

---

## 🔄 전체 수행 흐름 (8단계)

```
[1단계] ZAP 연결 확인
    ↓
[2단계] 로그인 구조 파악 (사용자가 API 정보를 제공하면 생략)
    ↓
[3단계] ZAP 컨텍스트 생성 및 인증 설정
    ↓
[4단계] Spider 크롤링 (인증 컨텍스트 적용)
    ↓
[5단계] Passive Scan + Active Scan
    ↓
[6단계] ZAP 결과 수집
    ↓
[7단계] 브라우저 수동 점검 (ZAP 미커버 항목)  ← 가이드 기준 추가
    ↓
[8단계] 21개 항목 기준 보고서 작성  ← 가이드 기준 추가
```

---

## 📋 가이드 21개 점검 항목 및 ZAP/수동 매핑

### 점검 항목 전체 목록

| 코드 | 점검 항목 | 중요도 | 점검 방법 | ZAP 커버리지 |
|------|----------|--------|----------|-------------|
| CI | 코드 인젝션 | 상 | ZAP Active Scan | ● 자동 |
| SI | SQL 인젝션 | 상 | ZAP Active Scan | ● 자동 |
| DI | 디렉터리 인덱싱 | 상 | 수동 (JS 디렉터리 접근 테스트) | ○ 수동 |
| EP | 에러 페이지 적용 미흡 | 상 | 수동 (비정상 URL 접근 테스트) | ○ 수동 |
| IL | 정보 누출 | 상 | ZAP Passive + 수동 (응답 헤더 분석) | ◐ 혼합 |
| XS | 크로스사이트 스크립팅 | 상 | ZAP Active Scan + CSP 분석 | ◐ 혼합 |
| CF | 크로스사이트 요청 위조 | 상 | 수동 (인증 구조/CSRF 토큰 분석) | ○ 수동 |
| SF | 서버사이드 요청 위조 | 상 | ZAP Active Scan | ● 자동 |
| BF | 약한 비밀번호 정책 | 상 | 수동 (회원가입 비밀번호 정책 확인) | ○ 수동 |
| IA | 불충분한 인증 절차 | 상 | 수동 (CAPTCHA, MFA 적용 확인) | ○ 수동 |
| IN | 불충분한 권한 검증 | 상 | 수동 (비인증 접근 차이 확인) | ○ 수동 |
| PR | 취약한 비밀번호 복구 | 상 | 수동 (비밀번호 복구 프로세스 확인) | ○ 수동 |
| PV | 프로세스 검증 누락 | 상 | 수동 (다단계 프로세스 우회 확인) | ○ 수동 |
| FU | 악성 파일 업로드 | 상 | 수동 (파일 업로드 기능 확인) | ○ 수동 |
| FD | 파일 다운로드 | 상 | 수동 (파일 다운로드 경로 조작 확인) | ○ 수동 |
| IS | 불충분한 세션 관리 | 상 | 수동 (토큰 저장 방식/쿠키 분석) | ○ 수동 |
| SN | 데이터 평문 전송 | 상 | ZAP Passive (HSTS 확인) + 수동 | ◐ 혼합 |
| CC | 쿠키 변조 | 상 | ZAP Passive (CORS) + 수동 (쿠키 속성) | ◐ 혼합 |
| AE | 관리자 페이지 노출 | 상 | 수동 (관리자 경로 접근 테스트) | ○ 수동 |
| AU | 자동화 공격 | 상 | 수동 (CAPTCHA/로그인 시도 제한 확인) | ○ 수동 |
| WM | 불필요한 Method 악용 | 상 | 수동 (HTTP Method 응답 테스트) | ○ 수동 |

### ZAP 자동 탐지 가능 항목 (Active/Passive Scan)
- **CI** (코드 인젝션): OS Command Injection, LDAP Injection, SSI, XPATH, SSTI
- **SI** (SQL 인젝션): Error-based, Blind, Time-based SQL Injection
- **XS** (XSS): Reflected XSS, Stored XSS + CSP 정책 분석 (Passive)
- **SF** (SSRF): Server Side Request Forgery
- **IL** (정보 누출): 서버 기술 스택 탐지, 응답 헤더 정보 노출 (Passive)
- **SN** (평문 전송): HSTS 미설정, Mixed Content (Passive)
- **CC** (쿠키/CORS): Cross-Domain Misconfiguration, 쿠키 속성 (Passive)

### 브라우저 수동 점검 필수 항목
- **DI, EP, AE, WM**: JavaScript fetch API로 자동화 가능
- **IS, AU, IA, BF**: 로그인 페이지 및 localStorage/쿠키 분석
- **CF, IN, PR, PV, FU, FD**: 기능별 수동 확인 필요

---

## [1단계] ZAP 연결 확인

```
호출: zap:get_version
기대: ZAP version: 2.x.x
```

---

## [2단계] 로그인 구조 파악

### 사용자가 로그인 API를 제공한 경우 → 이 단계 생략

### 브라우저로 캡처가 필요한 경우

```
1. tabs_context_mcp(createIfEmpty=true)
2. navigate(tabId, 로그인페이지URL)
3. wait(3초)
4. read_network_requests(tabId, clear=true)
5. read_page(tabId, filter="interactive") → 이메일/비밀번호 필드 ref 확인
6. form_input(ref=이메일필드, value=이메일)
7. form_input(ref=비밀번호필드, value=비밀번호)
8. computer(action=left_click, ref=로그인버튼)
9. wait(3초)
10. read_network_requests(tabId, urlPattern="login") → 로그인 API URL 캡처
```

캡처 후 확인할 것: 로그인 API URL, HTTP Method, Content-Type, 파라미터명

### 인증 저장 방식 확인 (선택)

```javascript
// javascript_tool에서 실행
JSON.stringify({
  localStorageKeys: Object.keys(localStorage),
  sessionStorageKeys: Object.keys(sessionStorage),
  cookieCount: document.cookie.split(';').length
})
```

---

## [3단계] ZAP 컨텍스트 생성 및 인증 설정

### 3-1. 컨텍스트 생성

```
zap:create_context(contextName="AuthScan-{사이트명}") → contextId
```

### 3-2. 스코프 URL 등록

```
zap:include_in_context(contextName, "https://example\\.com.*")
zap:include_in_context(contextName, "https://api\\.example\\.com.*")  ← API 도메인이 다를 때
```

### 3-3. 인증 방법 설정

**JSON 기반 (JWT/SPA — 가장 일반적)**:
```
zap:set_authentication_method(
  contextId,
  "jsonBasedAuthentication",
  "loginUrl={URL인코딩된 로그인API}&loginRequestData={URL인코딩된 JSON본문}"
)
```

loginRequestData 예시:
- 인코딩 전: `{"email":"{%username%}","password":"{%password%}"}`
- 인코딩 후: `%7B%22email%22%3A%22%7B%25username%25%7D%22%2C%22password%22%3A%22%7B%25password%25%7D%22%7D`

**Form 기반 (전통적 서버 렌더링)**:
```
zap:set_authentication_method(
  contextId,
  "formBasedAuthentication",
  "loginUrl={URL인코딩}&loginRequestData=username%3D%7B%25username%25%7D%26password%3D%7B%25password%25%7D"
)
```

### 3-4. 로그인/로그아웃 지시자

```
zap:set_logged_in_indicator(contextId, "\\Q마이페이지\\E|\\Q로그아웃\\E")
zap:set_logged_out_indicator(contextId, "\\Q로그인\\E|\\Q로그인/회원가입\\E")
```

### 3-5. 사용자 생성 및 인증 정보

```
zap:create_user(contextId, "tester") → userId
zap:set_authentication_credentials(contextId, userId,
  "username={URL인코딩된ID}&password={URL인코딩된PW}")
```

특수문자 인코딩: `@→%40`, `!→%21`, `#→%23`, `&→%26`

### 3-6. Forced User 활성화

```
zap:set_user_enabled(contextId, userId, true)
zap:set_forced_user(contextId, userId)
zap:set_forced_user_mode_enabled(true)
```

---

## [4단계] Spider 크롤링

```
zap:start_spider(url, contextName, maxChildren=10, recurse=true, subtreeOnly=true)
zap:get_spider_status(scanId) → 100% 확인
zap:get_spider_results(scanId) → 발견 URL 목록
```

SPA(Next.js, React, Vue)인 경우 Ajax Spider 추가:
```
zap:start_ajax_spider(url, contextName, subtreeOnly=true)
```

---

## [5단계] Passive Scan + Active Scan

```
zap:get_passive_scan_status → 0 records 확인
zap:start_active_scan(url, contextId, recurse=true)
zap:get_active_scan_status(scanId) → 100% 확인
```

---

## [6단계] ZAP 결과 수집

```
zap:get_alerts_summary(baseUrl)
zap:get_alerts(baseUrl, count=100, riskId="3")  ← High
zap:get_alerts(baseUrl, count=100, riskId="2")  ← Medium
zap:get_alerts(baseUrl, count=100, riskId="1")  ← Low
zap:get_alerts(baseUrl, count=100, riskId="0")  ← Info
```

---

## [7단계] 브라우저 수동 점검 (가이드 21개 항목 중 ZAP 미커버 항목)

### 수동 점검 수행 방법

Chrome 브라우저(Claude in Chrome MCP)에서 JavaScript를 실행하여 각 항목을 테스트합니다.
결과를 화면 오버레이로 표시한 후 스크린샷을 캡처하여 증적으로 활용합니다.

### 7-1. [WM] 불필요한 HTTP Method 점검

```javascript
// javascript_tool에서 실행
(async () => {
  const methods = ['OPTIONS','PUT','DELETE','PATCH','HEAD'];
  const results = [];
  for (const m of methods) {
    try { const r = await fetch(location.origin+'/',{method:m}); results.push({method:m,status:r.status}); }
    catch(e) { results.push({method:m,status:'ERR'}); }
  }
  return JSON.stringify(results);
})()
```
**판정 기준**: OPTIONS/PUT/DELETE/PATCH가 405(Method Not Allowed)이면 양호

### 7-2. [DI] 디렉터리 인덱싱 점검

```javascript
(async () => {
  const dirs = ['/_next/','/_next/static/','/images/','/fonts/','/api/','/uploads/','/public/'];
  const results = [];
  for (const d of dirs) {
    try {
      const r = await fetch(location.origin + d);
      const text = await r.text();
      const listing = text.includes('Index of') || text.includes('Directory listing') || text.includes('Parent Directory');
      results.push({path:d, status:r.status, listing});
    } catch(e) { results.push({path:d, status:'ERR', listing:false}); }
  }
  return JSON.stringify(results);
})()
```
**판정 기준**: 모든 경로가 404이고 디렉터리 목록 패턴이 없으면 양호

### 7-3. [EP] 에러 페이지 + [IL] 정보 누출 점검

```javascript
(async () => {
  const paths = ['/nonexistent-page-12345','/../../etc/passwd',"/<script>alert(1)</script>","/login?id=1' OR '1'='1"];
  const results = [];
  for (const p of paths) {
    try {
      const r = await fetch(location.origin + p);
      const text = await r.text();
      results.push({
        path:p, status:r.status,
        stackTrace: text.includes('Error:') || text.includes('at ') || text.includes('stack'),
        serverInfo: text.includes('nginx') || text.includes('Apache') || text.includes('Express') || text.includes('node_modules'),
        dbInfo: text.includes('SQL') || text.includes('mysql') || text.includes('postgres')
      });
    } catch(e) { results.push({path:p, status:'ERR'}); }
  }
  return JSON.stringify(results);
})()
```
**판정 기준**: 스택 트레이스, 서버 정보, DB 정보가 모두 미노출이면 양호

### 7-4. [AE] 관리자 페이지 노출 점검

```javascript
(async () => {
  const paths = ['/admin','/administrator','/admin/login','/manage','/manager','/cms','/wp-admin','/dashboard','/console','/backoffice','/phpmyadmin'];
  const results = [];
  for (const p of paths) {
    try { const r = await fetch(location.origin+p,{redirect:'follow'}); results.push({path:p,status:r.status}); }
    catch(e) { results.push({path:p,status:'ERR'}); }
  }
  return JSON.stringify(results);
})()
```
**판정 기준**: 모든 경로가 404이면 양호. 200 또는 302(로그인 리다이렉트)이면 추가 확인 필요.

### 7-5. [IS/CC] 세션 관리 + 쿠키 점검

```javascript
JSON.stringify({
  localStorageKeys: Object.keys(localStorage),
  sessionStorageKeys: Object.keys(sessionStorage),
  cookieCount: document.cookie.split(';').length,
  sensitiveInLocalStorage: ['accessToken','refreshToken','auth-storage','user-info']
    .filter(k => localStorage.getItem(k) !== null)
})
```
**판정 기준**: JWT 토큰이 localStorage에 있으면 취약 (HttpOnly 쿠키 권장). 토큰 미존재 또는 HttpOnly 쿠키이면 양호.

### 7-6. [AU/IA] 자동화 공격 + 인증 절차 점검

```javascript
// 로그인 페이지에서 실행
(() => {
  const checks = {
    reCAPTCHA: !!document.querySelector('[class*="recaptcha"],[id*="recaptcha"],script[src*="recaptcha"]'),
    hCaptcha: !!document.querySelector('[class*="hcaptcha"],[data-sitekey]'),
    captchaImage: !!document.querySelector('img[alt*="captcha"],img[src*="captcha"]'),
    loginLimitNotice: document.body.innerText.includes('시도 제한') || document.body.innerText.includes('잠금'),
    mfa: document.body.innerText.includes('2단계') || document.body.innerText.includes('OTP'),
  };
  return JSON.stringify(checks);
})()
```
**판정 기준**: CAPTCHA 미적용 + MFA 미지원이면 주의

### 7-7. [SN] 데이터 전송 보안 (응답 헤더 분석)

```javascript
(async () => {
  const r = await fetch(location.origin + '/robots.txt');
  const headers = {};
  ['strict-transport-security','content-security-policy','x-content-type-options',
   'x-frame-options','referrer-policy','permissions-policy'].forEach(h => {
    headers[h] = r.headers.get(h) ? 'SET' : 'NOT SET';
  });
  return JSON.stringify({isHTTPS: location.protocol === 'https:', headers});
})()
```
**판정 기준**: HTTPS + HSTS 적용이면 양호. HSTS 미설정이면 주의.

---

## [8단계] 보고서 작성

### 보고서 구성 (가이드 기준)

보고서는 다음 구조로 작성합니다:

```
1. 점검 개요
   - 점검 대상, 기술 스택, 점검 도구, 점검 방법, 점검 기준
   - 점검 기준: "2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 - Web Application(웹) 21개 항목"

2. 점검 결과 요약
   - 21개 항목별 판정 현황 테이블 (코드, 항목명, 판정, 점검 방법)
   - 판정 분포: 취약 N건, 주의 N건, 양호 N건, 수동점검 필요 N건

3. 항목별 상세 결과 (21개 항목 각각)
   - 항목 코드, 항목명, 판정 결과
   - 점검 방법 (ZAP 자동 / 수동 브라우저 / 혼합)
   - 상세 결과 설명
   - (취약/주의인 경우) 조치 방안

4. ZAP 자동화 스캔 상세
   - ZAP 탐지 취약점 유형별 상세 (CWE, 영향 URL, 설명, 조치 방안)

5. 종합 의견 및 권고사항
   - 우선순위별 조치 권고
   - 추가 점검 권고 사항
```

### 21개 항목 판정 기준

각 항목은 아래 기준으로 판정합니다:

| 판정 | 기준 |
|------|------|
| **양호** | ZAP 미탐지 + 수동 점검에서 문제 없음 |
| **취약** | ZAP 또는 수동 점검에서 명확한 취약점 확인 |
| **주의** | 직접적 취약점은 아니나 보안 강화 필요 (CSP 미흡, CAPTCHA 미적용 등) |
| **수동점검 필요** | 자동화 도구로 확인 불가, 별도 수동 테스트 필요 (파일 업로드, 권한 검증 등) |

### ZAP 결과 → 가이드 항목 매핑 규칙

ZAP에서 탐지된 알림을 가이드 항목에 매핑할 때 아래 규칙을 적용합니다:

| ZAP Alert | 매핑 항목 | 판정 |
|-----------|----------|------|
| SQL Injection | SI | 취약 |
| Cross Site Scripting (Reflected/Stored) | XS | 취약 |
| OS Command Injection / Code Injection | CI | 취약 |
| Server Side Request Forgery | SF | 취약 |
| CSP: script-src unsafe-inline | XS (관련) | 주의 |
| CSP: script-src unsafe-eval | XS (관련) | 주의 |
| CSP: style-src unsafe-inline | XS (관련) | 주의 |
| Cross-Domain Misconfiguration (CORS) | CC | 주의 |
| Strict-Transport-Security Not Set | SN | 주의 |
| X-Content-Type-Options Missing | IL | 주의 |
| X-Frame-Options Missing | CF (관련) | 주의 |
| Directory Browsing | DI | 취약 |
| Application Error Disclosure | EP | 취약 |
| Information Disclosure | IL | 주의 |
| Cookie Without Secure/HttpOnly Flag | IS, CC | 주의 |
| Tech Detected - HSTS | SN | 양호 (HSTS 적용 확인) |
| Tech Detected - Kong/기타 | IL | 주의 (기술 스택 노출) |
| Modern Web Application | - | 참고 (판정 제외) |

---

## ⚠️ 트러블슈팅

### set_authentication_method 타임아웃
- loginUrl도 URL 인코딩 필요: `https://` → `https%3A%2F%2F`

### Active Scan 특정 %에서 멈춤
- 방화벽/WAF 차단 가능성. 중간 결과로 보고서 작성 가능.

### SPA에서 Spider가 페이지 미발견
- Ajax Spider 추가 또는 사용자에게 주요 URL 목록 요청

### 인증이 작동하지 않음
- `get_authentication_method(contextId)` → 설정 확인
- `get_forced_user_status(contextId)` → 활성화 확인
- 로그인 API URL, 파라미터명, 지시자 정규식 재확인

---

## 📎 URL 인코딩 참조

| 원본 | 인코딩 | 용도 |
|------|--------|------|
| `https://` | `https%3A%2F%2F` | loginUrl |
| `@` | `%40` | 이메일 |
| `!` | `%21` | 비밀번호 |
| `{` | `%7B` | JSON |
| `}` | `%7D` | JSON |
| `"` | `%22` | JSON |
| `{%username%}` | `%7B%25username%25%7D` | ZAP 변수 |
| `{%password%}` | `%7B%25password%25%7D` | ZAP 변수 |

---

## 📊 Claude에게 점검 요청 시 프롬프트 템플릿

### A. 인증 스캔 + 가이드 기준 보고서 (로그인 API 아는 경우)

```
첨부한 ZAP_MCP_Playbook_v2.md를 참조하여 아래 사이트를 점검해줘.

[점검 대상]
- 사이트: https://example.com
- 로그인 API: https://example.com/api/auth/login (POST JSON)
- JSON: {"email":"{%username%}","password":"{%password%}"}
- ID/PW: user@test.com / password123
- 로그인 지시자: "로그아웃"
- 로그아웃 지시자: "로그인"

[점검 기준]
주요정보통신기반시설 기술적 취약점 분석·평가 가이드 (웹 21개 항목)

플레이북 [3단계]~[8단계]를 수행하고,
[8단계] 보고서 구성에 따라 21개 항목 기준 DOCX 보고서를 작성해줘.
```

### B. 인증 스캔 + 가이드 기준 보고서 (로그인 API 모르는 경우)

```
첨부한 ZAP_MCP_Playbook_v2.md를 참조하여 아래 사이트를 점검해줘.

[점검 대상]
- 사이트: https://example.com
- 로그인 페이지: https://example.com/login
- 로그인 API: 확인 필요
- ID/PW: user@test.com / password123
- 로그인 성공 시: "마이페이지" 표시
- 로그아웃 시: "로그인" 표시

[점검 기준]
주요정보통신기반시설 기술적 취약점 분석·평가 가이드 (웹 21개 항목)

플레이북 [2단계]~[8단계]를 수행해줘.
```

### C. 비인증 공개 사이트 점검

```
첨부한 ZAP_MCP_Playbook_v2.md를 참조하여 아래 사이트를 점검해줘.

[점검 대상]
- 사이트: https://example.com (비인증 공개 영역)
- 환경: 운영 (부하 최소화 필요)

[점검 기준]
주요정보통신기반시설 기술적 취약점 분석·평가 가이드 (웹 21개 항목)

인증 설정 없이 [4단계]~[8단계]를 수행해줘.
[7단계] 수동 점검도 함께 수행하고, 21개 항목 기준 보고서를 작성해줘.
```

---

*본 문서는 수정 없이 Claude에게 첨부하여 사용합니다. 사이트별 정보는 프롬프트에만 작성합니다.*
