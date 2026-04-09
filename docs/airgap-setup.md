# 에어갭(인터넷 차단) 환경 설치 가이드

인터넷이 차단된 환경에서 ZAP Web Scanner를 사용하기 위한 사전 준비 및 설치 절차입니다.

## 사전 준비 (인터넷 가능한 PC에서)

### 1. Python 의존성 다운로드

```bash
# 휠 파일 다운로드
pip download requests python-dotenv python-docx -d ./wheels/

# 확인
ls wheels/
# requests-*.whl, python_dotenv-*.whl, python_docx-*.whl, ...
```

### 2. Ollama + Gemma 4 모델

```bash
# Ollama 설치 파일 다운로드
# Windows: https://ollama.com/download/OllamaSetup.exe
# Linux: curl -fsSL https://ollama.com/install.sh | sh

# Gemma 4 모델 다운로드 (실행 후 모델 파일이 로컬에 캐시됨)
ollama pull gemma4:e4b

# 모델 파일 위치 확인
# Windows: %USERPROFILE%\.ollama\models\
# Linux: ~/.ollama/models/
```

모델 파일 위치:
- Windows: `C:\Users\<사용자>\.ollama\models\`
- Linux: `~/.ollama/models/`

전체 `.ollama/models/` 디렉터리를 USB 등으로 복사합니다.

### 3. OWASP ZAP

**Docker 사용 시:**
```bash
# 이미지 다운로드 + 저장
docker pull zaproxy/zap-stable
docker save zaproxy/zap-stable | gzip > zap-stable.tar.gz
```

**직접 설치 시:**
- https://www.zaproxy.org/download/ 에서 설치 파일 다운로드
- Windows: `ZAP_2_17_0_windows.exe`
- Linux: `ZAP_2_17_0_unix.sh`

### 4. Chromium (AJAX Spider용, 선택)

SPA(React, Vue, Next.js) 사이트 점검 시 필요합니다.

- https://download-chromium.appspot.com/ 에서 포터블 버전 다운로드

### 5. 스캐너 소스코드

```bash
# Git 클론 또는 ZIP 다운로드
git clone https://github.com/sungalex/zap-web-scanner.git
# 또는 GitHub에서 ZIP 다운로드
```

## 전달 목록 체크리스트

| 항목 | 파일/폴더 | 크기(대략) |
|------|----------|-----------|
| 스캐너 소스코드 | `zap-web-scanner/` | ~1MB |
| Python 휠 | `wheels/` | ~20MB |
| Ollama 설치 파일 | `OllamaSetup.exe` | ~100MB |
| Gemma 4 모델 | `.ollama/models/` | ~5GB |
| ZAP Docker 이미지 | `zap-stable.tar.gz` | ~1GB |
| ZAP 설치 파일 (대안) | `ZAP_2_17_0_*.exe` | ~200MB |
| Chromium (선택) | `chromium/` | ~200MB |

## 에어갭 환경 설치

### 1. Python 의존성 설치

```bash
# Python 3.9+ 가 이미 설치되어 있어야 함
pip install --no-index --find-links=./wheels/ requests python-dotenv python-docx
```

### 2. Ollama 설치 + 모델 복원

```bash
# Ollama 설치
# Windows: OllamaSetup.exe 실행
# Linux: sudo sh install.sh (오프라인 설치 스크립트)

# 모델 파일 복원 — 기존 모델 디렉터리를 동일 위치에 복사
# Windows: C:\Users\<사용자>\.ollama\models\ 에 복사
# Linux: ~/.ollama/models/ 에 복사

# Ollama 서버 시작
ollama serve

# 모델 확인
ollama list
# gemma4:e4b 가 표시되어야 함
```

### 3. ZAP 설치 및 실행

**Docker:**
```bash
# 이미지 로드
docker load < zap-stable.tar.gz

# 실행
docker run -u zap -p 8090:8090 zaproxy/zap-stable zap.sh \
  -daemon -host 0.0.0.0 -port 8090 -config api.disablekey=true
```

**직접 설치:**
```bash
# 설치 파일 실행 후
# Windows: "C:\Program Files\ZAP\zap.bat" -daemon -port 8090 -config api.disablekey=true
# Linux: /opt/zaproxy/zap.sh -daemon -port 8090 -config api.disablekey=true
```

### 4. 환경 검증

```bash
cd zap-web-scanner/
python web-scanner.py --check
```

출력 예:
```
[환경 검증]
  [ZAP] 연결 성공 - v2.17.0       ✓
  [Ollama] 연결 성공 - gemma4:e4b  ✓
  [Python] 의존성 확인              ✓
  [출력] 디렉터리 쓰기 가능         ✓
```

### 5. 스캔 실행

```bash
# 기본 스캔
python web-scanner.py https://target-site.local

# 메모리 절약 모드 (ZAP 스레드 제한)
python web-scanner.py https://target-site.local --scan-threads 1 --request-delay 500

# Active Scan 건너뛰기 (빠른 점검)
python web-scanner.py https://target-site.local --skip-active
```

## 네트워크 설정 참고

- ZAP 기본 포트: `8090` (localhost)
- Ollama 기본 포트: `11434` (localhost)
- 방화벽에서 스캐너 → 대상 시스템 HTTP/HTTPS 포트 허용 필요
- 방화벽 차단으로 Active Scan이 멈출 수 있음 — `--skip-active` 사용 또는 방화벽 예외 등록

## 문제 해결

| 증상 | 해결 |
|------|------|
| `ollama list`에 모델 미표시 | `.ollama/models/` 경로 확인, 파일 복사 누락 여부 |
| ZAP 연결 실패 | `curl http://localhost:8090/JSON/core/view/version/` 로 확인 |
| Active Scan 35%에서 메모리 급증 | `--scan-threads 1 --request-delay 1000` 사용 |
| Ollama 응답 타임아웃 | `--ollama-timeout 1800` (30분으로 연장) |
| 중간 실패 후 재개 | `--resume <scan_id>` (logs/ 폴더의 checkpoint 파일 참조) |
