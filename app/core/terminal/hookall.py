"""
VURA Terminal Monitoring — HookAll Engine
══════════════════════════════════════════
Discovers and reads from all interactive terminal sessions
on the system simultaneously.

How it works:
  1. Uses psutil to find all interactive shell processes
  2. Gets the tty/pts associated with each shell
  3. Attempts to read from each terminal device
  4. Aggregates all readable output into one result

Important limitations:
  - Reading from another process's tty requires appropriate permissions
  - On Linux: usually works if same user (owner of /dev/pts/N)
  - On macOS: /dev/ttys may require sudo for full access
  - On Windows: no tty concept; uses process snapshot instead

Thread safety: All public methods are thread-safe.
"""

from __future__ import annotations

import os
import sys
import time
import json
import shutil
import threading
from pathlib import Path
from typing import Optional

from .types import (
    HookAllResult, TerminalDescriptor, PlatformType,
    INTERACTIVE_SHELLS_UNIX, INTERACTIVE_SHELLS_WIN,
)


# ══════════════════════════════════════════════════════════════════════
# PLATFORM DETECTION
# ══════════════════════════════════════════════════════════════════════

def _is_windows() -> bool:
    return sys.platform.startswith("win")


def _is_macos() -> bool:
    return sys.platform == "darwin"


# ══════════════════════════════════════════════════════════════════════
# TERMINAL DISCOVERY
# ══════════════════════════════════════════════════════════════════════

class TerminalDiscovery:
    """
    Discovers all interactive terminal sessions on the system.

    Uses psutil for cross-platform process enumeration.
    """

    def __init__(self):
        self._lock = threading.Lock()

    def discover(self) -> list[TerminalDescriptor]:
        """
        Find all interactive terminals.

        Returns:
            List of TerminalDescriptor for each found terminal.
        """
        try:
            import psutil
        except ImportError:
            return self._fallback_discover()

        results: list[TerminalDescriptor] = []
        seen_ttys: set[str] = set()

        if _is_windows():
            for proc in psutil.process_iter(["pid", "name", "username"]):
                try:
                    info = proc.info
                    name = (info.get("name") or "").lower()
                    if name not in INTERACTIVE_SHELLS_WIN:
                        continue

                    tty_id = f"WIN-PID-{info['pid']}"
                    if tty_id in seen_ttys:
                        continue
                    seen_ttys.add(tty_id)

                    results.append(TerminalDescriptor(
                        pts_path=tty_id,
                        shell_name=name.replace(".exe", ""),
                        pid=info["pid"],
                        user=info.get("username") or "",
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        else:
            # Unix: filter by tty + interactive shell
            for proc in psutil.process_iter(["pid", "name", "terminal", "username"]):
                try:
                    info = proc.info
                    name = (info.get("name") or "").lower()
                    if name not in INTERACTIVE_SHELLS_UNIX:
                        continue

                    tty = info.get("terminal")
                    if not tty:
                        continue

                    tty_path = tty if tty.startswith("/dev/") else f"/dev/{tty}"
                    if tty_path in seen_ttys:
                        continue
                    seen_ttys.add(tty_path)

                    results.append(TerminalDescriptor(
                        pts_path=tty_path,
                        shell_name=name,
                        pid=info["pid"],
                        user=info.get("username") or "",
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        # Sort by terminal path
        results.sort(key=lambda t: t.pts_path)
        return results

    def _fallback_discover(self) -> list[TerminalDescriptor]:
        """
        Fallback discovery without psutil.

        Uses /dev/pts (Linux) or /dev/ttys (macOS) or who command.
        Less accurate — doesn't filter by shell type.
        """
        results: list[TerminalDescriptor] = []

        if _is_macos():
            dev = Path("/dev")
            try:
                for entry in sorted(dev.iterdir()):
                    if entry.name.startswith("ttys") and entry.name[4:].isdigit():
                        if os.access(entry, os.R_OK):
                            results.append(TerminalDescriptor(
                                pts_path=str(entry),
                                shell_name="?",
                                pid=0,
                            ))
            except OSError:
                pass

        elif not _is_windows():
            pts_dir = Path("/dev/pts")
            try:
                if pts_dir.is_dir():
                    for entry in sorted(pts_dir.iterdir()):
                        if entry.name.isdigit() and os.access(entry, os.R_OK):
                            results.append(TerminalDescriptor(
                                pts_path=str(entry),
                                shell_name="?",
                                pid=0,
                            ))
            except OSError:
                pass

        return results


# ══════════════════════════════════════════════════════════════════════
# EXCLUSION MANAGEMENT
# ══════════════════════════════════════════════════════════════════════

class ExclusionManager:
    """
    Manages the list of terminals excluded from HookAll.

    Persistence: stored as JSON in the data directory.
    """

    def __init__(self, data_dir: Optional[Path] = None):
        if data_dir is None:
            data_dir = Path(__file__).resolve().parents[3] / "data"
        self._file = data_dir / ".vura_hookall_exclusions.json"
        self._lock = threading.Lock()
        self._data_dir = data_dir

    def load(self) -> set[str]:
        """Load excluded terminal paths."""
        with self._lock:
            if not self._file.exists():
                return set()
            try:
                with open(self._file, "r") as f:
                    data = json.load(f)
                return set(data.get("excluded", []))
            except (json.JSONDecodeError, OSError):
                return set()

    def save(self, excluded: set[str]) -> None:
        """Save excluded terminal paths."""
        with self._lock:
            self._data_dir.mkdir(parents=True, exist_ok=True)
            with open(self._file, "w") as f:
                json.dump({"excluded": sorted(excluded)}, f, indent=2)

    def add(self, pts_path: str) -> None:
        """Add a terminal to the exclusion list."""
        excluded = self.load()
        excluded.add(pts_path)
        self.save(excluded)

    def remove(self, pts_path: str) -> None:
        """Remove a terminal from the exclusion list."""
        excluded = self.load()
        excluded.discard(pts_path)
        self.save(excluded)

    def is_excluded(self, pts_path: str) -> bool:
        """Check if a terminal is excluded."""
        return pts_path in self.load()


# ══════════════════════════════════════════════════════════════════════
# HOOKALL ENGINE
# ══════════════════════════════════════════════════════════════════════

class HookAllEngine:
    """
    Reads from all interactive terminals simultaneously.

    Usage:
        engine = HookAllEngine()

        # Discover terminals
        terminals = engine.discover()

        # Read from all
        result = engine.read_all()

        # Exclude a terminal
        engine.exclude("/dev/pts/2")
    """

    def __init__(self, data_dir: Optional[Path] = None):
        self.discovery = TerminalDiscovery()
        self.exclusions = ExclusionManager(data_dir)
        self._lock = threading.Lock()
        self._active = False

    @property
    def is_active(self) -> bool:
        with self._lock:
            return self._active

    def discover(self) -> list[TerminalDescriptor]:
        """
        Discover all interactive terminals, marking excluded ones.

        Returns:
            List of TerminalDescriptor with is_excluded flag set.
        """
        excluded = self.exclusions.load()
        terminals = self.discovery.discover()

        for t in terminals:
            t.is_excluded = t.pts_path in excluded

        return terminals

    def read_all(
        self,
        timeout: float = 2.0,
        max_bytes_per_tty: int = 500_000,
    ) -> HookAllResult:
        """
        Read from all non-excluded terminals.

        Parameters:
            timeout: Max seconds to spend reading each terminal
            max_bytes_per_tty: Cap per terminal (prevent memory issues)

        Returns:
            HookAllResult with aggregated output.
        """
        with self._lock:
            self._active = True

        terminals = self.discover()
        targets = [t for t in terminals if not t.is_excluded]
        excluded_paths = [t.pts_path for t in terminals if t.is_excluded]

        if not targets:
            with self._lock:
                self._active = False
            return HookAllResult(
                success=True,
                terminals_found=len(terminals),
                terminals_read=0,
                excluded=excluded_paths,
            )

        # Read from each terminal in parallel
        results_lock = threading.Lock()
        total_bytes = 0
        total_read = 0
        errors: list[str] = []
        output_parts: list[str] = []

        def read_one(desc: TerminalDescriptor) -> None:
            nonlocal total_bytes, total_read
            try:
                text = self._read_terminal(desc.pts_path, timeout, max_bytes_per_tty)
                if text:
                    with results_lock:
                        output_parts.append(
                            f"\n{'='*60}\n"
                            f"TERMINAL: {desc.pts_path} "
                            f"(shell: {desc.shell_name}, pid: {desc.pid})\n"
                            f"{'='*60}\n\n"
                            f"{text}\n"
                        )
                        total_bytes += len(text)
                        total_read += 1
            except Exception as e:
                with results_lock:
                    errors.append(f"{desc.pts_path}: {e}")

        threads = []
        for desc in targets:
            t = threading.Thread(target=read_one, args=(desc,), daemon=True)
            t.start()
            threads.append(t)

        # Wait for all readers
        for t in threads:
            t.join(timeout=timeout + 5)

        with self._lock:
            self._active = False

        aggregated = "\n".join(output_parts) if output_parts else ""

        return HookAllResult(
            success=bool(aggregated),
            terminals_found=len(terminals),
            terminals_read=total_read,
            total_bytes=total_bytes,
            aggregated_text=aggregated,
            errors=errors,
            excluded=excluded_paths,
        )

    def _read_terminal(
        self,
        pts_path: str,
        timeout: float,
        max_bytes: int,
    ) -> str:
        """
        Read from a single terminal device.

        On Linux: reads from /dev/pts/N
        On macOS: reads from /dev/ttysN
        On Windows: reads process console buffer (limited)

        Returns cleaned text (ANSI stripped).
        """
        if _is_windows():
            return self._read_win_terminal(pts_path)

        # Unix: read from pts/tty device
        if not os.path.exists(pts_path):
            return ""

        if not os.access(pts_path, os.R_OK):
            return ""

        try:
            with open(pts_path, "rb") as f:
                data = b""
                start = time.time()
                while time.time() - start < timeout:
                    chunk = os.read(f.fileno(), 4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) >= max_bytes:
                        data = data[:max_bytes]
                        break

            # Strip ANSI
            from .unix_pty import strip_ansi
            return strip_ansi(data)

        except (OSError, IOError, PermissionError):
            return ""

    def _read_win_terminal(self, pts_id: str) -> str:
        """
        Read from a Windows shell process.

        Uses ctypes to read console screen buffer.
        Limited — returns process info only if full read not possible.
        """
        if not pts_id.startswith("WIN-PID-"):
            return ""

        try:
            pid = int(pts_id.split("-")[-1])
        except ValueError:
            return ""

        # On Windows, we can't easily read another process's console
        # without attaching to it (which would freeze it).
        # Return metadata about the process instead.
        try:
            import psutil
            proc = psutil.Process(pid)
            cmdline = " ".join(proc.cmdline())[:200]
            return f"[Process {pid}] — {proc.name()} — {cmdline}"
        except Exception:
            return ""

    # ── Exclusion ──────────────────────────────────────────────────

    def exclude(self, pts_path: str) -> None:
        """Exclude a terminal from future read_all calls."""
        self.exclusions.add(pts_path)

    def unexclude(self, pts_path: str) -> None:
        """Remove a terminal from the exclusion list."""
        self.exclusions.remove(pts_path)

    def get_excluded(self) -> list[str]:
        """Get list of excluded terminal paths."""
        return sorted(self.exclusions.load())


# ══════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ══════════════════════════════════════════════════════════════════════

_hookall_instance: Optional[HookAllEngine] = None
_hookall_lock = threading.Lock()


def get_hookall(data_dir: Optional[Path] = None) -> HookAllEngine:
    """Get or create the global HookAllEngine instance."""
    global _hookall_instance
    with _hookall_lock:
        if _hookall_instance is None:
            _hookall_instance = HookAllEngine(data_dir)
        return _hookall_instance


def discover_terminals() -> list[TerminalDescriptor]:
    """Discover all interactive terminals."""
    return get_hookall().discover()


def read_all_terminals(**kwargs) -> HookAllResult:
    """Read from all non-excluded terminals."""
    return get_hookall().read_all(**kwargs)


def exclude_terminal(pts_path: str) -> None:
    """Exclude a terminal from HookAll."""
    get_hookall().exclude(pts_path)


def get_excluded_terminals() -> list[str]:
    """Get list of excluded terminals."""
    return get_hookall().get_excluded()
