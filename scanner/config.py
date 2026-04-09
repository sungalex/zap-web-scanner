"""설정 및 데이터 로딩"""

import os
import json
from dataclasses import dataclass, field
from typing import Optional, Dict
from dotenv import load_dotenv

load_dotenv()

# 패키지 루트 경로 (scanner/ 의 상위 = 프로젝트 루트)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ============================================================
# 타임아웃 상수
# ============================================================
ZAP_REQUEST_TIMEOUT = 30        # ZAP API 요청
MANUAL_CHECK_TIMEOUT = 10       # 수동 점검 HTTP 요청
OLLAMA_TIMEOUT = 900            # Ollama AI 분석 (15분)
PASSIVE_SCAN_TIMEOUT = 120      # Passive Scan 대기
PASSIVE_SCAN_MAX_RETRIES = 3    # Passive Scan 재시도
SPIDER_POLL_INTERVAL = 2        # Spider 진행률 폴링
AJAX_SPIDER_POLL_INTERVAL = 3   # Ajax Spider 폴링
PASSIVE_SCAN_POLL_INTERVAL = 3  # Passive Scan 폴링
ACTIVE_SCAN_POLL_INTERVAL = 5   # Active Scan 진행률 폴링


@dataclass
class ScanConfig:
    """스캔 설정"""
    target_url: str = ""
    zap_url: str = os.getenv("ZAP_API_URL", "http://localhost:8090")
    zap_key: str = os.getenv("ZAP_API_KEY", "")
    ollama_url: str = os.getenv("OLLAMA_URL", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "gemma4:e4b")
    skip_active: bool = False
    auth_config: Optional[Dict] = None
    # 스캔 제어
    scan_threads: Optional[int] = None       # 호스트당 스캔 스레드 (기본: ZAP 기본값)
    request_delay: Optional[int] = None      # 요청 간 딜레이(ms)
    # 타임아웃 오버라이드
    passive_timeout: Optional[int] = None    # Passive Scan 타임아웃(초)
    ollama_timeout: Optional[int] = None     # Ollama AI 타임아웃(초)


# ============================================================
# 데이터 로딩
# ============================================================
_kisa_items_cache = None
_mapping_rules_cache = None


def load_kisa_items() -> list:
    """21개 점검 항목 로드"""
    global _kisa_items_cache
    if _kisa_items_cache is None:
        path = os.path.join(BASE_DIR, "data", "kisa_2026_items.json")
        with open(path, "r", encoding="utf-8") as f:
            _kisa_items_cache = json.load(f)
    return _kisa_items_cache


def load_mapping_rules() -> dict:
    """ZAP Alert 매핑 규칙 로드"""
    global _mapping_rules_cache
    if _mapping_rules_cache is None:
        path = os.path.join(BASE_DIR, "data", "zap_alert_mapping.json")
        with open(path, "r", encoding="utf-8") as f:
            _mapping_rules_cache = json.load(f)
    return _mapping_rules_cache
