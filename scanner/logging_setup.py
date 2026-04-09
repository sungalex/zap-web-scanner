"""통합 로깅 설정"""

import logging
import warnings
from urllib3.exceptions import InsecureRequestWarning

logger = logging.getLogger("web-scanner")
logger.setLevel(logging.INFO)
logging.captureWarnings(True)
warnings.filterwarnings("default")
warnings.filterwarnings("ignore", category=InsecureRequestWarning)


def setup_file_handler(log_path: str):
    """로그 파일 핸들러 설정 (기존 핸들러 교체)"""
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fh)


def log_and_print(msg: str, level: str = "info", end: str = "\n"):
    """로그 + 콘솔 동시 출력 (이중 호출 제거용)"""
    getattr(logger, level)(msg)
    print(msg, end=end, flush=True)
