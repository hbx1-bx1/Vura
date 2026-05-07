"""
VURA GUI — Ghost Engine (Hybrid)
═══════════════════════════════════
Hybrid wrapper that delegates to app.core.terminal (pty-based) internally
while preserving the exact same API the GUI expects.

Fallback: if core.terminal is unavailable, uses direct subprocess methods.
"""

from __future__ import annotations

import os
import signal
import platform
from pathlib import Path
from typing import Optional, List, Dict

from gui.engine.helpers import (
    IS_WIN, find_terminal, launch_terminal, clean_ansi,
)

# ── Project paths ────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parents[2]
_DATA = _ROOT / "data"
_LOG = _DATA / ".vura_session.log"


# ══════════════════════════════════════════════════════════════════════
# GhostEngine — hybrid class using core.terminal with fallback
# ══════════════════════════════════════════════════════════════════════

class GhostEngine:
    """
    Manages Ghost Monitor sessions for the GUI.

    Delegates to app.core.terminal.TerminalSession when available.
    Falls back to direct subprocess launch if core.terminal is unavailable.
    """

    def __init__(self):
        self._pid: Optional[int] = None
        self._silent = False
        self._core_session = None  # TerminalSession from core.terminal
        self._use_core = False

    @property
    def pid(self) -> Optional[int]:
        return self._pid

    @property
    def silent(self) -> bool:
        return self._silent

    @silent.setter
    def silent(self, v: bool) -> None:
        self._silent = v

    # ── Start ────────────────────────────────────────────────────────

    def start(self) -> tuple[bool, str]:
        """Start Ghost Monitor recording. Returns (success, message)."""
        term = find_terminal()
        if not term:
            return False, "No terminal found! Install a terminal emulator."

        _DATA.mkdir(parents=True, exist_ok=True)

        try:
            from app.core.terminal import TerminalSession
            self._core_session = TerminalSession(
                session_id="gui_ghost",
                log_file=_LOG,
                visible=True,
                stream_mode="batch",
            )
            info = self._core_session.start()
            self._use_core = True
            self._pid = info.pid
            return True, (
                f"\u2714 Terminal: {info.shell} (PID {info.pid})\n"
                f"Recording \u2192 {_LOG}"
            )
        except Exception:
            return self._start_fallback(term)

    def _start_fallback(self, term: str) -> tuple[bool, str]:
        """Fallback: direct subprocess launch without core.terminal."""
        if IS_WIN:
            log_str = str(_LOG)
            cmd = (
                f"Start-Transcript -Path '{log_str}' -Append; "
                "Write-Host '[VURA Ghost Monitor] Recording...' -ForegroundColor Green; "
                "cmd; "
                "Stop-Transcript"
            )
        else:
            import shutil
            if not shutil.which("script"):
                return False, "'script' not found. Install util-linux."
            sh = os.environ.get("SHELL", "/bin/bash")
            banner = r"echo -e '\033[1;32m[VURA Ghost Monitor]\033[0m Recording...'"
            if platform.system() == "Darwin":
                cmd = f"{banner}; script -q -a {_LOG} {sh}"
            else:
                cmd = f"{banner}; script -q -a -c {sh} {_LOG}"

        try:
            p, tname = launch_terminal(cmd, term)
            self._pid = p.pid
            self._use_core = False
            return True, (
                f"\u2714 Terminal: {tname} (PID {p.pid})\n"
                f"Recording \u2192 {_LOG}"
            )
        except Exception as e:
            return False, f"Error launching terminal: {e}"

    # ── Stop ─────────────────────────────────────────────────────────

    def stop(self) -> Optional[str]:
        """Stop recording and return cleaned data."""
        if self._use_core and self._core_session:
            try:
                return self._core_session.stop()
            except Exception:
                pass

        if self._pid:
            try:
                os.kill(self._pid, signal.SIGTERM)
            except OSError:
                pass
            self._pid = None

        if not _LOG.exists():
            return None
        try:
            with open(_LOG, "r", encoding="utf-8", errors="ignore") as f:
                raw = f.read()
        except OSError:
            return None
        clean = clean_ansi(raw)
        try:
            _LOG.unlink()
        except OSError:
            pass
        return clean if len(clean) > 5 else None

    # ── Discard ──────────────────────────────────────────────────────

    def discard(self) -> None:
        """Stop and discard all session data."""
        if self._use_core and self._core_session:
            try:
                self._core_session.discard()
            except Exception:
                pass
            self._core_session = None
            self._use_core = False
            return

        if self._pid:
            try:
                os.kill(self._pid, signal.SIGTERM)
            except OSError:
                pass
            self._pid = None

        for f in [_LOG, _DATA / ".vura_session_meta.json"]:
            try:
                if f.exists():
                    f.unlink()
            except OSError:
                pass

    # ── Status ───────────────────────────────────────────────────────

    def is_active(self) -> bool:
        """Check if a session is currently active."""
        if self._use_core and self._core_session:
            return self._core_session.is_active

        if self._pid:
            try:
                os.kill(self._pid, 0)
                return True
            except OSError:
                self._pid = None
        return _LOG.exists()

    def get_size(self) -> str:
        """Return human-readable log file size."""
        if _LOG.exists():
            s = _LOG.stat().st_size
            return f"{s/1024:.1f}KB" if s > 1024 else f"{s}B"
        return "0"

    # ── HookAll ──────────────────────────────────────────────────────

    def hookall(self) -> tuple[bool, str, int]:
        """
        Read all open terminal sessions.
        Returns (success, message, terminal_count).
        """
        _DATA.mkdir(parents=True, exist_ok=True)

        try:
            from app.core.terminal import HookAllEngine
            engine = HookAllEngine(_DATA)
            terminals = engine.discover()
            targets = [t for t in terminals if not t.is_excluded]
            excluded = [t for t in terminals if t.is_excluded]

            if not terminals:
                return False, "", 0

            result = engine.read_all(timeout=3.0)
            if result.aggregated_text:
                return True, result.aggregated_text, result.terminals_read
            return True, f"Found {len(terminals)} terminal(s)", len(terminals)

        except Exception:
            return self._hookall_fallback()

    def _hookall_fallback(self) -> tuple[bool, str, int]:
        """Fallback: direct /dev/tty scanning."""
        import platform
        terminals = []
        if IS_WIN:
            try:
                import psutil
                win_shells = {"cmd.exe", "powershell.exe", "pwsh.exe"}
                for proc in psutil.process_iter(["pid", "name", "status"]):
                    try:
                        info = proc.info
                        pname = (info.get("name") or "").lower()
                        if pname in win_shells and info.get("status") != "zombie":
                            terminals.append(f"WIN-PID-{info['pid']}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except ImportError:
                pass
        elif platform.system() == "Darwin":
            dev = Path("/dev")
            try:
                for entry in dev.iterdir():
                    if entry.name.startswith("ttys") and entry.name[4:].isdigit():
                        if os.access(entry, os.R_OK):
                            terminals.append(str(entry))
            except OSError:
                pass
        else:
            pts_dir = Path("/dev/pts")
            if pts_dir.is_dir():
                for entry in pts_dir.iterdir():
                    if entry.name.isdigit() and os.access(entry, os.R_OK):
                        terminals.append(str(entry))

        if not terminals:
            return False, "", 0
        if IS_WIN:
            return True, f"Found {len(terminals)} shell(s): {', '.join(terminals)}", len(terminals)
        try:
            import subprocess
            out = subprocess.check_output(["who"], text=True, stderr=subprocess.DEVNULL)
            return True, out.strip(), len(terminals)
        except Exception:
            return True, f"Found {len(terminals)} terminals: {', '.join(terminals)}", len(terminals)

    # ── Terminal Listing ─────────────────────────────────────────────

    def list_terminals(self) -> List[Dict[str, object]]:
        """
        List active interactive terminals.
        Returns list of dicts: path, name, shell, pid
        """
        interactive = {
            "zsh", "bash", "sh", "fish", "tcsh", "csh", "dash", "ksh",
        }
        win_shells = {"cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe"}
        results = []
        seen = set()

        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name", "terminal", "status"]):
                try:
                    info = proc.info
                    pname = (info.get("name") or "").lower()
                    status = info.get("status", "")
                    pid = info.get("pid", 0)
                    if status in ("zombie", "dead"):
                        continue

                    if IS_WIN:
                        if pname not in win_shells:
                            continue
                        win_id = f"WIN-PID-{pid}"
                        if win_id in seen:
                            continue
                        seen.add(win_id)
                        results.append({
                            "path": win_id,
                            "name": f"PID-{pid}",
                            "shell": pname.replace(".exe", ""),
                            "pid": pid,
                        })
                    else:
                        tty = info.get("terminal")
                        if not tty:
                            continue
                        tty_path = tty if tty.startswith("/dev/") else f"/dev/{tty}"
                        tty_name = Path(tty_path).name
                        if tty_path in seen:
                            continue
                        if pname not in interactive:
                            continue
                        seen.add(tty_path)
                        results.append({
                            "path": tty_path,
                            "name": tty_name,
                            "shell": pname,
                            "pid": pid,
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except ImportError:
            import platform
            if IS_WIN:
                pass
            elif platform.system() == "Darwin":
                dev = Path("/dev")
                try:
                    for entry in sorted(dev.iterdir()):
                        if entry.name.startswith("ttys") and entry.name[4:].isdigit():
                            if os.access(entry, os.R_OK):
                                results.append({"path": str(entry), "name": entry.name, "shell": "?", "pid": 0})
                except OSError:
                    pass
            else:
                pts_dir = Path("/dev/pts")
                if pts_dir.is_dir():
                    for entry in sorted(pts_dir.iterdir()):
                        if entry.name.isdigit() and os.access(entry, os.R_OK):
                            results.append({"path": str(entry), "name": entry.name, "shell": "?", "pid": 0})

        results.sort(key=lambda x: x["name"])
        return results

    # ── Exclusion ────────────────────────────────────────────────────

    def exclude_terminals(self, pts_list: List[str]) -> tuple[bool, str]:
        """Exclude terminals from HookAll."""
        _DATA.mkdir(parents=True, exist_ok=True)
        exc_file = _DATA / ".vura_exclude_pts"
        try:
            with open(exc_file, "a") as f:
                for pts in pts_list:
                    f.write(pts + "\n")
            return True, f"Excluded {len(pts_list)} terminal(s): {', '.join(pts_list)}"
        except Exception as ex:
            return False, f"Error: {ex}"

    def get_excluded(self) -> List[str]:
        """Get list of excluded terminals."""
        exc_file = _DATA / ".vura_exclude_pts"
        if not exc_file.exists():
            return []
        try:
            with open(exc_file, "r") as f:
                return [l.strip() for l in f.readlines() if l.strip()]
        except Exception:
            return []


# ══════════════════════════════════════════════════════════════════════
# Module-level singleton for backward compatibility with old gui.py
# ══════════════════════════════════════════════════════════════════════

_engine: Optional[GhostEngine] = None


def _get_engine() -> GhostEngine:
    """Get or create the global GhostEngine singleton."""
    global _engine
    if _engine is None:
        _engine = GhostEngine()
    return _engine


def reset_engine() -> None:
    """Reset the global engine (for testing or reinitialization)."""
    global _engine
    _engine = None


# ── Backward-compatible function wrappers ────────────────────────────

def ghost_start() -> tuple[bool, str]:
    return _get_engine().start()


def ghost_stop() -> Optional[str]:
    return _get_engine().stop()


def ghost_discard() -> None:
    return _get_engine().discard()


def ghost_active() -> bool:
    return _get_engine().is_active()


def ghost_size() -> str:
    return _get_engine().get_size()


def ghost_hookall() -> tuple[bool, str, int]:
    return _get_engine().hookall()


def ghost_list_terminals() -> List[Dict[str, object]]:
    return _get_engine().list_terminals()


def ghost_exclude_terminals(pts_list: List[str]) -> tuple[bool, str]:
    return _get_engine().exclude_terminals(pts_list)


def ghost_get_excluded() -> List[str]:
    return _get_engine().get_excluded()
