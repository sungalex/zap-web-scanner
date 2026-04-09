"""재시도 유틸리티 (지수 백오프)"""

import time
import random
import functools
from scanner.logging_setup import logger


def retry_with_backoff(max_retries=3, base_delay=2.0, max_delay=30.0,
                       exceptions=(Exception,), description=""):
    """지수 백오프 + 지터를 적용하는 재시도 데코레이터

    Args:
        max_retries: 최대 재시도 횟수 (0이면 재시도 없음)
        base_delay: 초기 대기 시간(초)
        max_delay: 최대 대기 시간(초)
        exceptions: 재시도 대상 예외 튜플
        description: 로그 메시지에 사용할 작업 설명
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            desc = description or func.__name__
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_retries:
                        delay = min(base_delay * (2 ** attempt), max_delay)
                        jitter = random.uniform(0, delay * 0.3)
                        wait = delay + jitter
                        logger.warning("[재시도] %s 실패 (%d/%d): %s - %.1f초 후 재시도",
                                       desc, attempt + 1, max_retries, e, wait)
                        time.sleep(wait)
                    else:
                        logger.error("[재시도] %s 최종 실패 (%d회 시도): %s",
                                     desc, max_retries + 1, e)

            raise last_exception
        return wrapper
    return decorator


def retry_call(func, *args, max_retries=3, base_delay=2.0, max_delay=30.0,
               exceptions=(Exception,), description="", default=None, **kwargs):
    """함수 호출을 재시도하는 유틸리티 (데코레이터 대신 직접 호출용)

    실패 시 default 반환 (예외를 raise하지 않음).
    """
    desc = description or getattr(func, '__name__', 'call')
    last_exception = None

    for attempt in range(max_retries + 1):
        try:
            return func(*args, **kwargs)
        except exceptions as e:
            last_exception = e
            if attempt < max_retries:
                delay = min(base_delay * (2 ** attempt), max_delay)
                jitter = random.uniform(0, delay * 0.3)
                wait = delay + jitter
                logger.warning("[재시도] %s 실패 (%d/%d): %s - %.1f초 후 재시도",
                               desc, attempt + 1, max_retries, e, wait)
                time.sleep(wait)
            else:
                logger.error("[재시도] %s 최종 실패 (%d회 시도): %s",
                             desc, max_retries + 1, e)

    return default
