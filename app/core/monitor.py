"""
VURA Ghost Monitor — Compatibility Layer
══════════════════════════════════════════
Compatibility layer that delegates to the new pty-based terminal module.

This file preserves the exact same API as the old monitor.py so that
cli.py and other existing code continue to work without modification.

New code should import from app.core.terminal instead:
    from app.core.terminal import TerminalSession, HookAllEngine
"""

from __future__ import annotations

import os
import json
import datetime
import platform
from pathlib import Path
from typing import Optional

from rich.console import Console

from app.core.terminal import (
    TerminalSession,
    HookAllEngine,
    TerminalState,
    get_hookall,
)
from app.utils.logger import log

console = Console()

# ══════════════════════════════════════════════════════════════════════
# PATHS (kept for backward compatibility)
# ══════════════════════════════════════════════════════════════════════

IS_WIN = os.name == "nt"
_PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()
_DATA_DIR = _PROJECT_ROOT / "data"
LOG_FILE = _DATA_DIR / ".vura_session.log"
META_FILE = _DATA_DIR / ".vura_session_meta.json"

# ── Global session reference (compatibility with old global state) ─
_active_session: Optional[TerminalSession] = None
_hookall_engine: Optional[HookAllEngine] = None


def _get_session() -> TerminalSession:
    """Get or create the global TerminalSession."""
    global _active_session
    if _active_session is None:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        _active_session = TerminalSession(
            session_id="ghost",
            log_file=LOG_FILE,
            visible=True,
            stream_mode="batch",
        )
    return _active_session


def _get_hookall() -> HookAllEngine:
    """Get or create the global HookAllEngine."""
    global _hookall_engine
    if _hookall_engine is None:
        _hookall_engine = get_hookall(_DATA_DIR)
    return _hookall_engine


# ══════════════════════════════════════════════════════════════════════
# ANSI CLEANING (kept for backward compatibility)
# ══════════════════════════════════════════════════════════════════════

def clean_ansi_escape_sequences(text: str) -> str:
    """حذف ANSI escape codes من النص — ألوان Terminal وحركات المؤشر."""
    from app.core.terminal import strip_ansi_str
    return strip_ansi_str(text)


# ══════════════════════════════════════════════════════════════════════
# SESSION METADATA (backward compatibility)
# ══════════════════════════════════════════════════════════════════════

def _save_session_meta(action: str) -> None:
    """حفظ بيانات الجلسة الوصفية."""
    meta = {
        "action": action,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "shell": os.environ.get("SHELL", os.environ.get("COMSPEC", "unknown")),
        "os": platform.system(),
        "cwd": os.getcwd(),
    }
    try:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(META_FILE, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    except Exception:
        pass


def _get_session_size() -> str:
    """حجم ملف الجلسة الحالي."""
    if LOG_FILE.exists():
        size = LOG_FILE.stat().st_size
        if size < 1024:
            return f"{size} bytes"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.1f} MB"
    return "0 bytes"


# ══════════════════════════════════════════════════════════════════════
# GHOST MONITOR (delegates to TerminalSession)
# ══════════════════════════════════════════════════════════════════════

def start_ghost_monitor(silent: bool = False) -> None:
    """
    بدء تسجيل Terminal session.

    Delegates to TerminalSession.start() with visible=True.
    """
    global _active_session
    _DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not silent:
        if LOG_FILE.exists():
            size = _get_session_size()
            console.print(
                f"\n[bold cyan][+] Resuming previous VURA Ghost Session ({size})...[/bold cyan]"
            )
        else:
            console.print(
                f"\n[bold green][+] Starting new VURA Ghost Monitor...[/bold green]"
            )
        console.print(
            "[bold yellow][!] Session is recording. "
            "Type [bold red]'exit'[/bold red] to pause/save.[/bold yellow]\n"
        )

    _save_session_meta("start")

    try:
        _active_session = TerminalSession(
            session_id="ghost",
            log_file=LOG_FILE,
            visible=True,
            stream_mode="batch",
        )
        info = _active_session.start()
        log.info("Ghost Monitor started", shell=info.shell, os=platform.system())
    except Exception as e:
        if not silent:
            console.print(f"[bold red][!] Error during monitoring: {e}[/bold red]")
        log.exception("Ghost Monitor error", e)


def end_ghost_monitor() -> Optional[str]:
    """
    إيقاف الـ Ghost Monitor واستخراج البيانات النظيفة.

    Returns:
        str : البيانات المُنظّفة من ANSI codes — جاهزة للـ AI
        None : إذا لم تكن هناك جلسة نشطة
    """
    global _active_session

    if not LOG_FILE.exists():
        console.print(
            "[bold red][!] No active session found. Run 'vura -H' first.[/bold red]"
        )
        log.warn("end_ghost_monitor called but no session file found")
        return None

    # If there's an active session, stop it properly
    if _active_session and _active_session.is_active:
        clean_data = _active_session.stop()
    else:
        # Fallback: read from log file directly
        try:
            raw_data = LOG_FILE.read_text(encoding="utf-8", errors="ignore")
            clean_data = clean_ansi_escape_sequences(raw_data)
        except Exception as e:
            console.print(
                f"[bold red][!] Cannot read session file: {e}[/bold red]"
            )
            log.error("Cannot read session file", error=str(e))
            return None

    # Clean up log file
    try:
        LOG_FILE.unlink()
    except Exception:
        pass

    try:
        if META_FILE.exists():
            META_FILE.unlink()
    except Exception:
        pass

    _active_session = None

    char_count = len(clean_data)
    console.print(
        f"[bold green][+] Captured {char_count:,} characters for the final report![/bold green]"
    )
    log.info("Ghost Monitor ended", chars=char_count)

    _save_session_meta("end")

    if char_count < 10:
        console.print(
            "[bold yellow][!] Warning: Very short session. Report may be empty.[/bold yellow]"
        )
        log.warn("Very short session captured", chars=char_count)

    return clean_data


def is_session_active() -> bool:
    """هل يوجد session نشطة حالياً."""
    if _active_session and _active_session.is_active:
        return True
    return LOG_FILE.exists()


def get_session_info() -> Optional[dict]:
    """معلومات عن الجلسة الحالية."""
    if not LOG_FILE.exists() and not (_active_session and _active_session.is_active):
        return None

    info: dict = {"size": _get_session_size(), "path": str(LOG_FILE)}

    if _active_session and _active_session.is_active:
        terminal_info = _active_session.get_info()
        info.update({
            "state": terminal_info.state.value,
            "shell": terminal_info.shell,
            "bytes_captured": terminal_info.bytes_captured,
            "pid": terminal_info.pid,
        })

    if META_FILE.exists():
        try:
            with open(META_FILE, "r", encoding="utf-8") as f:
                info.update(json.load(f))
        except Exception:
            pass

    return info


def discard_session() -> None:
    """حذف الجلسة بدون توليد تقرير."""
    global _active_session

    deleted = False
    if _active_session and _active_session.is_active:
        _active_session.discard()
        deleted = True
        _active_session = None

    for f in [LOG_FILE, META_FILE]:
        try:
            if f.exists():
                f.unlink()
                deleted = True
        except Exception:
            pass

    if deleted:
        console.print("[yellow][-] Session discarded.[/yellow]")
        log.info("Session discarded by user")
    else:
        console.print("[dim]No active session to discard.[/dim]")


# ══════════════════════════════════════════════════════════════════════
# HOOKALL (delegates to HookAllEngine)
# ══════════════════════════════════════════════════════════════════════

def exclude_terminal() -> None:
    """
    استبعاد الطرفية الحالية من hookall.
    الأمر: vura -e
    """
    # Get current terminal
    import subprocess
    try:
        pts = subprocess.check_output(
            ["tty"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        if IS_WIN:
            pts = f"WIN-PID-{os.getpid()}"
        else:
            pts = ""

    if not pts or "not a tty" in pts:
        console.print(
            "[bold red][!] Cannot detect current terminal. "
            "Are you in a TTY?[/bold red]"
        )
        return

    engine = _get_hookall()
    engine.exclude(pts)

    console.print(f"[bold yellow][-] Terminal excluded: {pts}[/bold yellow]")
    console.print("[dim]This terminal will NOT be recorded by hookall.[/dim]")
    log.info("Terminal excluded from hookall", pts=pts)


def start_hookall(silent: bool = False) -> None:
    """
    بدء تسجيل جميع الطرفيات المفتوحة في النظام.
    الأمر: vura -Ha

    Delegates to HookAllEngine.read_all() with parallel reading.
    """
    engine = _get_hookall()
    terminals = engine.discover()

    if not terminals:
        if not silent:
            console.print("[bold red][!] No active terminals found.[/bold red]")
        return

    targets = [t for t in terminals if not t.is_excluded]
    excluded = [t for t in terminals if t.is_excluded]

    # Auto-exclude current terminal
    import subprocess
    try:
        current_pts = subprocess.check_output(
            ["tty"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        current_pts = ""

    if current_pts:
        engine.exclude(current_pts)
        targets = [t for t in targets if t.pts_path != current_pts]

    if not targets:
        if not silent:
            console.print(
                "[bold yellow][!] All terminals are excluded. "
                "Nothing to record.[/bold yellow]"
            )
            console.print(
                f"[dim]Found: {len(terminals)} | "
                f"Excluded: {len(excluded) + 1}[/dim]"
            )
        return

    if not silent:
        console.print(
            f"\n[bold green][+] VURA Hookall — "
            f"Reading {len(targets)} terminal(s)...[/bold green]"
        )
        for t in targets:
            console.print(f"    [cyan]→ {t.pts_path} ({t.shell_name})[/cyan]")
        if excluded:
            console.print(
                f"    [dim]Excluded: {len(excluded)} terminal(s)[/dim]"
            )
        console.print(
            "\n[bold yellow][!] Reading now. "
            "Run 'vura -R' to generate report.[/bold yellow]\n"
        )

    # Read from all terminals (parallel, thread-safe)
    result = engine.read_all(timeout=3.0)

    if result.aggregated_text:
        # Save aggregated data for later use
        hookall_log = _DATA_DIR / ".vura_hookall.log"
        try:
            hookall_log.write_text(
                result.aggregated_text, encoding="utf-8"
            )
        except OSError:
            pass

        if not silent:
            console.print(
                f"[bold green][+] HookAll captured "
                f"{result.total_bytes:,} chars from "
                f"{result.terminals_read} terminal(s)[/bold green]"
            )
            log.info(
                "HookAll completed",
                terminals=result.terminals_read,
                bytes=result.total_bytes,
            )

    if result.errors and not silent:
        for err in result.errors:
            console.print(f"    [dim red]✘ {err}[/dim red]")


def stop_hookall() -> Optional[str]:
    """
    إيقاف hookall وإرجاع البيانات المجمّعة.

    Reads the aggregated hookall log file.
    """
    hookall_log = _DATA_DIR / ".vura_hookall.log"

    if hookall_log.exists():
        try:
            raw_data = hookall_log.read_text(
                encoding="utf-8", errors="ignore"
            )
            clean_data = clean_ansi_escape_sequences(raw_data)
            hookall_log.unlink()

            console.print(
                f"[bold green][+] Hookall captured "
                f"{len(clean_data):,} characters from all terminals![/bold green]"
            )
            log.info("Hookall ended", chars=len(clean_data))
            return clean_data
        except Exception:
            pass

    # Fallback: try the engine directly
    engine = _get_hookall()
    if engine.is_active:
        result = engine.read_all(timeout=2.0)
        if result.aggregated_text:
            return clean_ansi_escape_sequences(result.aggregated_text)

    return None


def is_hookall_active() -> bool:
    """هل hookall يعمل حالياً."""
    hookall_log = _DATA_DIR / ".vura_hookall.log"
    return hookall_log.exists()


def clear_excluded() -> None:
    """مسح قائمة الطرفيات المستبعدة."""
    engine = _get_hookall()
    for pts in engine.get_excluded():
        engine.unexclude(pts)
    console.print("[green][+] Exclude list cleared.[/green]")
