"""
VURA Logger — Centralized Logging System
═════════════════════════════════════════
Logs all VURA operations to data/vura.log with rotation.

Usage:
    from app.utils.logger import log

    log.info("Scan started", target="example.com")
    log.error("API failed", provider="openrouter", error="timeout")
    log.scan("recon", target="example.com", status="completed")
"""

import os
import datetime
import traceback
from pathlib import Path
from typing import Optional

_PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()
_LOG_DIR      = _PROJECT_ROOT / "data"
_LOG_FILE     = _LOG_DIR / "vura.log"
MAX_LOG_SIZE_MB = 10
MAX_LOG_FILES   = 5


class VuraLogger:
    """نظام تسجيل موحّد لكل عمليات VURA."""

    def __init__(self, log_file=None):
        self.log_file = Path(log_file) if log_file else _LOG_FILE
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def _rotate_if_needed(self):
        """تدوير الملف إذا تجاوز الحجم الأقصى."""
        try:
            if not self.log_file.exists():
                return
            if self.log_file.stat().st_size / (1024 * 1024) < MAX_LOG_SIZE_MB:
                return
            for i in range(MAX_LOG_FILES - 1, 0, -1):
                old = Path(f"{self.log_file}.{i}")
                new_path = Path(f"{self.log_file}.{i + 1}")
                if old.exists():
                    if i + 1 >= MAX_LOG_FILES:
                        old.unlink()
                    else:
                        old.rename(new_path)
            self.log_file.rename(Path(f"{self.log_file}.1"))
        except Exception:
            pass

    def _write(self, level, message, **kwargs):
        self._rotate_if_needed()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] [{level}] {message}"
        if kwargs:
            details = " | ".join(f"{k}={v}" for k, v in kwargs.items() if v is not None)
            if details:
                entry += f" | {details}"
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(entry + "\n")
        except Exception:
            pass

    def info(self, message, **kwargs):
        self._write("INFO", message, **kwargs)

    def warn(self, message, **kwargs):
        self._write("WARN", message, **kwargs)

    def error(self, message, **kwargs):
        self._write("ERROR", message, **kwargs)

    def debug(self, message, **kwargs):
        self._write("DEBUG", message, **kwargs)

    def scan(self, scan_type, target, status, **kwargs):
        self._write("SCAN", f"{scan_type} -> {target} [{status}]", **kwargs)

    def api_call(self, provider, model, status, duration_ms=None, **kwargs):
        msg = f"API {provider}/{model} [{status}]"
        if duration_ms:
            msg += f" ({duration_ms}ms)"
        self._write("API", msg, **kwargs)

    def license_event(self, event, hwid, **kwargs):
        self._write("LICENSE", f"{event} | HWID: {hwid}", **kwargs)

    def exception(self, message, exc: Optional[Exception] = None):
        self._write("EXCEPTION", message)
        if exc:
            for line in traceback.format_exception(type(exc), exc, exc.__traceback__):
                self._write("TRACE", line.rstrip())

    def tail(self, lines=30) -> str:
        if not self.log_file.exists():
            return "No log file found."
        try:
            with open(self.log_file, "r", encoding="utf-8", errors="ignore") as f:
                all_lines = f.readlines()
            return "".join(all_lines[-lines:])
        except Exception:
            return "Cannot read log file."

    def clear(self):
        try:
            with open(self.log_file, "w") as f:
                f.write("")
        except Exception:
            pass


log = VuraLogger()
