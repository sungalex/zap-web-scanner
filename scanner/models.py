"""데이터 모델"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List
from datetime import datetime


@dataclass
class Finding:
    """취약점 진단 결과 항목"""
    code: str
    name: str
    full_name: str
    importance: str
    verdict: str           # 취약, 주의, 양호, 수동점검 필요
    scan_method_desc: str  # 실제 수행한 점검 방법 설명
    detail: str            # 상세 결과
    remediation: str = ""  # 조치 방안 (취약/주의 시)
    zap_alerts: list = field(default_factory=list)
    ai_analysis: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(**d)


@dataclass
class ScanCheckpoint:
    """스캔 중단점 — 실패 시 재개용"""
    scan_id: str                           # 타임스탬프 기반 ID
    target_url: str
    config: dict = field(default_factory=dict)
    completed_stages: List[int] = field(default_factory=list)
    stage_data: Dict = field(default_factory=dict)
    analyzed_items: List[str] = field(default_factory=list)  # 분석 완료 항목 코드
    last_updated: str = ""

    def save(self, log_dir: str = "logs"):
        """체크포인트를 JSON 파일로 저장"""
        self.last_updated = datetime.now().isoformat()
        path = os.path.join(log_dir, f"checkpoint_{self.scan_id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, ensure_ascii=False, indent=2)
        return path

    @classmethod
    def load(cls, path: str) -> "ScanCheckpoint":
        """JSON 파일에서 체크포인트 로드"""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)

    def mark_stage(self, stage: int, data: dict = None):
        """단계 완료 기록"""
        if stage not in self.completed_stages:
            self.completed_stages.append(stage)
        if data:
            self.stage_data[str(stage)] = data
