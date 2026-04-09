# 주요정보통신기반시설 웹 취약점 자동 진단 시스템

- 2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 - Web Application(웹) **21개 항목** 기준

- Claude Desktop, ZAP(with ZAP MCP Server), Chrome 브라우저를 이용한 웹 취약점 점검 자동화 프로세스를 인터넷 접속이 차단된 환경에서 사용할 수 있도록, Ollama, Gemma4:e4b, ZAP, chromium 기반으로 자동화

## 웹 스캐너 8 Step

![웹스캐너 8 스탭](./web-scanner_8step_workflow.svg)

## 빠른 시작

```bash
# 의존성 설치 (최초 1회)
pip install requests python-dotenv python-docx

# 비인증 스캔
python web-scanner.py https://대상URL

# 인증 스캔
python web-scanner.py https://대상URL \
  --login-url https://api.example.com/auth/login \
  --login-data '{"email":"{%username%}","password":"{%password%}"}' \
  --username user@test.com \
  --password password123 \
  --logged-in "\\Q로그아웃\\E" \
  --logged-out "\\Q로그인\\E" \
  --api-backend https://api.example.com

# 환경 검증만 (스캔 없이)
python web-scanner.py --check

# 메모리 절약 모드 (ZAP 스레드 제한 + 요청 딜레이)
python web-scanner.py https://대상URL --scan-threads 1 --request-delay 500

# Active Scan 건너뛰기 (빠른 점검)
python web-scanner.py https://대상URL --skip-active

# 실패 시 중단점에서 재개
python web-scanner.py --resume <scan_id>

# 타임아웃 조정
python web-scanner.py https://대상URL --passive-timeout 180 --ollama-timeout 1800
```

## 주요 기능

| 기능 | 설명 |
|------|------|
| **KISA 2026 가이드 21개 항목 자동 진단** | ZAP 자동 스캔 + HTTP 수동 점검 + AI 분석을 하나의 워크플로로 통합 |
| **AI 취약점 분석** | Ollama + Gemma 4 로컬 AI가 항목별 판정(취약/주의/양호/수동점검 필요) 및 종합 의견 생성 |
| **DOCX/JSON 보고서 자동 생성** | 가이드 양식에 맞는 DOCX 보고서 + 기계 판독용 JSON 자동 생성 |
| **실패 시 중단점 재실행** | `--resume` 로 실패한 단계부터 재개, AI 분석은 항목별 부분 재실행 |
| **ZAP 리소스 제어** | `--scan-threads`, `--request-delay` 로 메모리 사용량 및 타겟 부하 제어 |
| **자동 재시도** | ZAP API, Ollama, 수동 점검 HTTP 요청 실패 시 지수 백오프 자동 재시도 |
| **ZAP 결과 보존** | Spider URL, 경고 원시 데이터, 수동 점검 결과를 `logs/zap/`에 JSON 저장 |
| **에어갭 환경 지원** | 인터넷 차단 환경 설치 가이드 제공 ([airgap-setup.md](docs/airgap-setup.md)) |

## 패키지 구조

```
web-scanner.py              # CLI 진입점
scanner/
    config.py               # 설정, 타임아웃 상수, 데이터 로더
    models.py               # Finding, ScanCheckpoint 데이터클래스
    logging_setup.py         # 통합 로거
    retry.py                # 재시도 데코레이터 (지수 백오프)
    orchestrator.py         # 8단계 스캔 워크플로 + 체크포인트
    zap/
        client.py           # ZAP REST API 클라이언트 (재시도 포함)
        manual_checks.py    # DI/EP/AE/WM/SN/CC 수동 점검
        throttle.py         # 메모리/트래픽 제어
    analysis/
        analyzer.py         # Ollama + Gemma 4 AI 분석 (재시도 포함)
        mapper.py           # ZAP 경고 → KISA 항목 매핑
    report/
        json_report.py      # JSON 보고서
        docx_report.py      # DOCX 보고서
data/
    kisa_2026_items.json    # 21개 점검 항목 정의
    zap_alert_mapping.json  # ZAP Alert 매핑 규칙
prompts/
    item_analysis.txt       # AI 분석 프롬프트 템플릿
    summary.txt             # 종합 의견 프롬프트 템플릿
```

## 21개 점검 항목

| 코드 | 항목 | ZAP 커버리지 | 점검 방법 |
|------|------|:---:|------|
| CI | 코드 인젝션 | ● | ZAP Active Scan |
| SI | SQL 인젝션 | ● | ZAP Active Scan |
| DI | 디렉터리 인덱싱 | ○ | 수동 (HTTP 요청) |
| EP | 에러 페이지 적용 미흡 | ○ | 수동 (비정상 URL 테스트) |
| IL | 정보 누출 | ◐ | ZAP Passive + 수동 |
| XS | 크로스사이트 스크립팅 | ◐ | ZAP Active + CSP 분석 |
| CF | 크로스사이트 요청 위조 | ○ | 수동 (인증 구조 분석) |
| SF | 서버사이드 요청 위조 | ● | ZAP Active Scan |
| BF | 약한 비밀번호 정책 | ○ | 수동 |
| IA | 불충분한 인증 절차 | ○ | 수동 (CAPTCHA/MFA) |
| IN | 불충분한 권한 검증 | ○ | 수동 (IDOR 테스트) |
| PR | 취약한 비밀번호 복구 | ○ | 수동 |
| PV | 프로세스 검증 누락 | ○ | 수동 |
| FU | 악성 파일 업로드 | ○ | 수동 |
| FD | 파일 다운로드 | ○ | 수동 |
| IS | 불충분한 세션 관리 | ○ | 수동 (토큰/쿠키 분석) |
| SN | 데이터 평문 전송 | ◐ | ZAP Passive + 수동 |
| CC | 쿠키 변조 | ◐ | ZAP Passive + 수동 |
| AE | 관리자 페이지 노출 | ○ | 수동 (경로 접근 테스트) |
| AU | 자동화 공격 | ○ | 수동 (CAPTCHA 확인) |
| WM | 불필요한 Method 악용 | ○ | 수동 (HTTP Method 테스트) |

● = ZAP 자동  ◐ = ZAP + 수동 혼합  ○ = 수동 점검

## 출력 보고서

```
reports/
  vuln_report_YYYYMMDD_HHMMSS.docx       # 가이드 양식 DOCX
  vuln_report_YYYYMMDD_HHMMSS.json       # 기계 판독용 JSON
logs/
  scan_YYYYMMDD_HHMMSS.log              # 스캔 로그
  checkpoint_YYYYMMDD_HHMMSS.json       # 중단점 (재실행용)
  zap/
    spider_urls_YYYYMMDD_HHMMSS.json    # Spider 발견 URL
    alerts_raw_YYYYMMDD_HHMMSS.json     # ZAP 경고 원시 데이터
    alerts_summary_YYYYMMDD_HHMMSS.json # 경고 요약
    manual_checks_YYYYMMDD_HHMMSS.json  # 수동 점검 결과
    findings_YYYYMMDD_HHMMSS.json       # AI 분석 중간 결과
```

### DOCX 보고서 구조
1. 점검 개요 (대상, 도구, 방법, 기준)
2. 점검 결과 요약 (판정 분포 + 21개 항목 현황 테이블)
3. 점검 항목별 상세 결과 (21개 항목 각각)
4. ZAP 자동화 스캔 상세 결과 (CWE, URL, 설명)
5. 종합 의견 및 권고사항 (AI 생성)

## CLI 옵션

| 옵션 | 설명 |
|------|------|
| `--skip-active` | Active Scan 건너뛰기 (Passive만 실행) |
| `--check` | 환경 검증만 실행 (스캔 없음) |
| `--resume <id>` | 체크포인트에서 재개 (scan_id 또는 파일 경로) |
| `--scan-threads N` | 호스트당 ZAP 스캔 스레드 수 (메모리 절약: 1) |
| `--request-delay N` | ZAP 요청 간 딜레이(ms, 타겟 부하 제어) |
| `--passive-timeout N` | Passive Scan 타임아웃(초, 기본: 120) |
| `--ollama-timeout N` | Ollama AI 타임아웃(초, 기본: 900) |
| `--zap-url URL` | ZAP REST API 엔드포인트 |
| `--ollama-url URL` | Ollama 서버 엔드포인트 |
| `--model NAME` | Ollama 모델명 |

## 사용 환경

이 프로젝트는 두 가지 환경에서 사용할 수 있습니다.

### 환경 A: 에어갭/로컬 자동화 (이 도구)

인터넷이 차단된 환경 또는 CLI 자동화가 필요한 경우. Ollama + Gemma 4 로컬 AI로 분석합니다.

| 구성 요소 | 용도 | 비고 |
|----------|------|------|
| **Python 3.9+** | 스캐너 실행 | `pip install requests python-dotenv python-docx` |
| **OWASP ZAP** | 프록시/스캐너 (port 8090) | Docker 또는 로컬 설치 |
| **Ollama + gemma4:e4b** | AI 취약점 분석 (port 11434) | `ollama pull gemma4:e4b` |

`.env` 파일을 프로젝트 루트에 생성하여 기본값을 변경할 수 있습니다:

```bash
# .env
ZAP_API_URL=http://localhost:8090
ZAP_API_KEY=your-zap-api-key
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=gemma4:e4b
```

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `ZAP_API_URL` | `http://localhost:8090` | ZAP REST API 엔드포인트 |
| `ZAP_API_KEY` | (빈 문자열) | ZAP API 키 (`api.disablekey=true` 시 불필요) |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama 서버 엔드포인트 |
| `OLLAMA_MODEL` | `gemma4:e4b` | AI 분석에 사용할 Ollama 모델명 |

> CLI 인자(`--zap-url`, `--model` 등)가 `.env` 값보다 우선합니다.

에어갭(인터넷 차단) 환경 설치는 [airgap-setup.md](docs/airgap-setup.md) 참조.

### 환경 B: Claude Desktop + ZAP MCP (대화형)

인터넷이 가능한 환경에서 Claude Desktop을 통해 대화형으로 점검하는 경우.

| 구성 요소 | 용도 | 비고 |
|----------|------|------|
| **Claude Desktop** | AI 에이전트 | 윈도우/맥 앱 |
| **OWASP ZAP** | 프록시/스캐너 (port 8080) | API 키 설정 필요 |
| **.NET SDK 8.0+** | ZAP MCP 서버 빌드 | `dotnet tool install -g dotnet-zap-mcp` |

- ZAP MCP 서버 설정: [Claude-ZAP_MCP_설정_가이드.md](docs/Claude-ZAP_MCP_설정_가이드.md)
- 점검 수행 플레이북: [Claude-ZAP_MCP_Playbook.md](docs/Claude-ZAP_MCP_Playbook.md)

## 주의사항

- **반드시 사전 승인을 받고 수행하세요**
- Active Scan은 실제 공격 패턴을 전송합니다
- AI 분석은 참고용이며 최종 판정은 보안 전문가가 수행해야 합니다
- `수동점검 필요` 항목은 별도 수동 테스트가 필요합니다
