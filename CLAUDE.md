# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ZAP Web Scanner — 주요정보통신기반시설 웹 취약점 자동 진단 시스템 (Critical Information Communications Infrastructure Web Vulnerability Automated Diagnostic System). Automates KISA 2026 web vulnerability assessments (21 items) using OWASP ZAP + local Gemma 4 AI analysis via Ollama.

Single-file Python CLI tool: `web-scanner.py` (~1170 lines). No build system or test framework.

## Running the Scanner

```bash
# Basic scan
python web-scanner.py <target_url>

# Skip active scan (faster, passive-only)
python web-scanner.py <target_url> --skip-active

# Authenticated scan (JSON login)
python web-scanner.py <target_url> --login-url https://example.com/api/login --login-data '{"id":"user","pw":"pass"}' --logged-in "dashboard" --logged-out "login"

# Custom ZAP/Ollama endpoints
python web-scanner.py <target_url> --zap-url http://localhost:8090 --zap-key <key> --ollama-url http://localhost:11434 --model gemma4:e4b
```

## Environment Setup

Two external services must be running:

1. **OWASP ZAP** — proxy/scanner on port 8090 (Docker or local install)
2. **Ollama** — local LLM server on port 11434 with `gemma4:e4b` model installed

Python dependencies: `requests`, `python-dotenv`, `python-docx`.

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `ZAP_API_URL` | `http://localhost:8090` | ZAP REST API endpoint |
| `ZAP_API_KEY` | hardcoded default | ZAP API key |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama server endpoint |
| `OLLAMA_MODEL` | `gemma4:e4b` | LLM model for analysis |

## Architecture

### 8-Stage Scan Workflow (`run_scan()`)

1. **Connection Check** — validate ZAP and Ollama connectivity
2. **Context Setup** — create ZAP context with optional authentication (JSON or form-based)
3. **Spider Crawl** — discover URLs via standard + AJAX spider
4. **Passive + Active Scan** — ZAP automated vulnerability testing
5. **Result Collection** — retrieve ZAP alerts with risk/CWE/URL data
6. **Manual Checks** — HTTP-based tests for items ZAP cannot automate (directory indexing, error pages, admin pages, HTTP methods, security headers)
7. **AI Analysis** — per-item Gemma 4 verdict assignment + executive summary
8. **Report Generation** — output JSON + DOCX (via python-docx)

### Key Components

- **`KISA_2026_ITEMS`** (top of file) — configuration database of 21 assessment items, each with code, name, importance level, scan method, ZAP coverage indicator (●/◐/○), CWE IDs, and alert-matching patterns
- **`ZAP_ALERT_MAPPING_RULES`** — maps ZAP alert names to KISA item codes and verdicts
- **`ZAPScanner`** class — REST API wrapper for OWASP ZAP (spider, scan, alerts, manual HTTP checks, context/auth setup)
- **`GemmaAnalyzer`** class — Ollama integration for per-item AI analysis and summary generation
- **`Finding`** dataclass — represents a single vulnerability finding with verdict (취약/주의/양호/수동점검 필요)
- **`generate_docx_report()`** — creates the DOCX report using python-docx

### Verdict System

Findings use a 4-level Korean verdict: 취약 (vulnerable), 주의 (caution), 양호 (safe), 수동점검 필요 (manual review needed).

## Code Conventions

- All user-facing output and assessment terminology is in Korean
- Assessment item codes are 2-letter uppercase (e.g., SI, XS, DI, CF)
- The scanner communicates with ZAP entirely through its REST API (JSON responses)
- DOCX generation uses python-docx with XML helpers for cell shading
