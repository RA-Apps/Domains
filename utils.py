"""Утилиты общего назначения."""

import time
from typing import Callable, Optional
from datetime import datetime


def retry(func: Callable, *args, max_attempts=3, delay=1, **kwargs):
    """Универсальная обёртка для повторных попыток выполнения функции."""
    for attempt in range(max_attempts):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(f"Retry {attempt+1}/{max_attempts} for {func.__name__}: {e}")
            if attempt < max_attempts - 1:
                time.sleep(delay)
    return None


def format_date(date) -> Optional[str]:
    """Преобразует объект даты whois или список в строку YYYY-MM-DD."""
    if isinstance(date, list):
        date = date[0] if date else None
    if date:
        try:
            return date.strftime("%Y-%m-%d")
        except AttributeError:
            pass
    return None


def parse_cert_date(value: str) -> str:
    """Преобразует дату из сертификата в формат YYYY-MM-DD."""
    try:
        dt = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return value
