# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ZAP Web Scanner — 주요정보통신기반시설 웹 취약점 자동 진단 시스템 (Critical Information Communications Infrastructure Web Vulnerability Automated Diagnostic System). Automates KISA 2026 web vulnerability assessments (21 items) using OWASP ZAP + local Gemma 4 AI analysis via Ollama.

Modular Python CLI tool with package structure under `scanner/`.

## Running the Scanner

```bash
# Basic scan
python web-scanner.py <target_url>

# Skip active scan (faster, passive-only)
python web-scanner.py <target_url> --skip-active

# Authenticated scan (JSON login)
python web-scanner.py <target_url> --login-url https://example.com/api/login --login-data '{"id":"user","pw":"pass"}' --logged-in "dashboard" --logged-out "login"

# Memory-saving mode (reduce ZAP threads + add request delay)
python web-scanner.py <target_url> --scan-threads 1 --request-delay 500

# Environment check only (no scan)
python web-scanner.py --check

# Resume from checkpoint after failure
python web-scanner.py --resume <scan_id>

# Custom timeouts
python web-scanner.py <target_url> --passive-timeout 180 --ollama-timeout 1800
```

## Environment Setup

Two external services must be running:

1. **OWASP ZAP** — proxy/scanner on port 8090 (Docker or local install)
2. **Ollama** — local LLM server on port 11434 with `gemma4:e4b` model installed

Python dependencies: `requests`, `python-dotenv`, `python-docx`.

For air-gapped environments, see `docs/airgap-setup.md`.

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `ZAP_API_URL` | `http://localhost:8090` | ZAP REST API endpoint |
| `ZAP_API_KEY` | (empty) | ZAP API key |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama server endpoint |
| `OLLAMA_MODEL` | `gemma4:e4b` | LLM model for analysis |

## Package Structure

```
web-scanner.py              # CLI entry point (~100 lines)
scanner/
    config.py               # ScanConfig dataclass, timeout constants, data loaders
    models.py               # Finding, ScanCheckpoint dataclasses
    logging_setup.py        # Unified logger + log_and_print()
    retry.py                # retry_with_backoff decorator, retry_call utility
    orchestrator.py         # ScanOrchestrator — 8-stage workflow with checkpoint
    zap/
        client.py           # ZAPClient — REST API wrapper (with retry)
        manual_checks.py    # ManualChecker — DI/EP/AE/WM/SN/CC checks
        throttle.py         # ScanThrottle — memory/traffic control
    analysis/
        analyzer.py         # GemmaAnalyzer — Ollama AI (with retry)
        mapper.py           # map_alerts_to_items() — ZAP alert → KISA mapping
    report/
        json_report.py      # JSON report generation
        docx_report.py      # DOCX report generation (python-docx)
data/
    kisa_2026_items.json    # 21 assessment items definition
    zap_alert_mapping.json  # ZAP alert → KISA item mapping rules
prompts/
    item_analysis.txt       # AI prompt template for per-item analysis
    summary.txt             # AI prompt template for executive summary
```

## Architecture

### 8-Stage Scan Workflow (`ScanOrchestrator`)

1. **Connection Check** — validate ZAP and Ollama connectivity
2. **Context Setup** — create ZAP context with optional authentication
3. **Spider Crawl** — discover URLs via standard + AJAX spider
4. **Passive + Active Scan** — ZAP automated vulnerability testing (with throttle)
5. **Result Collection** — retrieve ZAP alerts
6. **Manual Checks** — HTTP-based tests for items ZAP cannot automate
7. **AI Analysis** — per-item Gemma 4 verdict assignment + executive summary
8. **Report Generation** — output JSON + DOCX

Each stage saves a checkpoint to `logs/checkpoint_{scan_id}.json` for resume support.

### Key Features

- **Retry with backoff**: ZAP API calls, Ollama requests, manual checks all retry on failure
- **Checkpoint/Resume**: `--resume <scan_id>` restarts from the last completed stage; AI analysis resumes per-item
- **ZAP Throttle**: `--scan-threads` and `--request-delay` control memory usage and target load
- **ZAP data preservation**: Raw alerts, spider URLs, manual check results saved to `logs/zap/`
- **External prompts**: AI prompt templates in `prompts/` — editable without code changes
- **External data**: KISA items and mapping rules in `data/` JSON files

### Verdict System

Findings use a 4-level Korean verdict: 취약 (vulnerable), 주의 (caution), 양호 (safe), 수동점검 필요 (manual review needed).

## Code Conventions

- All user-facing output and assessment terminology is in Korean
- Assessment item codes are 2-letter uppercase (e.g., SI, XS, DI, CF)
- The scanner communicates with ZAP entirely through its REST API (JSON responses)
- Use `log_and_print()` from `scanner/logging_setup.py` instead of separate `logger.info()` + `print()` calls
- Timeouts are defined as constants in `scanner/config.py`, not hardcoded in methods
- DOCX generation uses python-docx with XML helpers for cell shading
