"""
VURA Terminal Monitoring — Windows ConPTY Implementation
══════════════════════════════════════════════════════════
Windows terminal session manager using ConPTY (Console Pseudo Terminal).

ConPTY is available on Windows 10 (1809+) and Windows 11.
It provides true pseudo-terminal semantics similar to Unix PTYs.

Fallback: PowerShell Start-Transcript (always available).

Priority order:
  1. pywinpty library (pip install pywinpty) — best ConPTY support
  2. ctypes-based ConPTY direct API calls — no extra deps
  3. PowerShell Start-Transcript — reliable fallback
"""

from __future__ import annotations

import os
import sys
import time
import shutil
import signal
import threading
from pathlib import Path
from typing import Optional, Iterator, Callable, Any

from .types import (
    TerminalState, TerminalOutput, TerminalInfo,
    DEFAULT_READ_BUFFER, DEFAULT_STREAM_INTERVAL,
)


# ══════════════════════════════════════════════════════════════════════
# ANSI CLEANING (same as Unix, kept here for independence)
# ══════════════════════════════════════════════════════════════════════

import re

_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def strip_ansi(raw_bytes: bytes) -> str:
    """Decode bytes and strip ANSI escape sequences."""
    text = raw_bytes.decode("utf-8", errors="replace")
    text = _ANSI_RE.sub("", text)
    text = _CTRL_RE.sub("", text)
    return text


# ══════════════════════════════════════════════════════════════════════
# WINDOWS CONPTY SESSION
# ══════════════════════════════════════════════════════════════════════

class WinConptySession:
    """
    Manages a Windows terminal session.

    Tries three backends in order:
      1. pywinpty — Python bindings for ConPTY (requires pip install)
      2. PowerShell Start-Transcript — always available
      3. cmd.exe with logging — basic fallback
    """

    def __init__(
        self,
        session_id: str,
        shell: Optional[str] = None,
        log_file: Optional[Path] = None,
        visible: bool = True,
        stream_mode: str = "realtime",
        on_output: Optional[Callable[[TerminalOutput], None]] = None,
    ):
        self.session_id = session_id
        self.shell = shell or self._detect_shell()
        self.log_file = log_file
        self.visible = visible
        self.stream_mode = stream_mode
        self.on_output = on_output

        # Internal state
        self._lock = threading.Lock()
        self._state = TerminalState.IDLE
        self._backend: Optional[str] = None  # "pywinpty", "transcript", "cmd"
        self._pty: Optional[Any] = None      # pywinpty agent or None
        self._process: Optional[Any] = None  # subprocess.Popen
        self._reader_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._output_buffer: list[bytes] = []
        self._total_bytes = 0
        self._error: Optional[str] = None
        self._start_time: Optional[float] = None

    @property
    def state(self) -> TerminalState:
        with self._lock:
            return self._state

    @property
    def is_active(self) -> bool:
        return self.state in (
            TerminalState.STARTING,
            TerminalState.RUNNING,
            TerminalState.PAUSED,
        )

    @property
    def total_bytes(self) -> int:
        with self._lock:
            return self._total_bytes

    @property
    def backend(self) -> Optional[str]:
        with self._lock:
            return self._backend

    # ── Shell Detection ────────────────────────────────────────────

    @staticmethod
    def _detect_shell() -> str:
        """Find the best available Windows shell."""
        if shutil.which("wt"):
            return "wt"
        if shutil.which("pwsh"):
            return "pwsh"
        if shutil.which("powershell"):
            return "powershell"
        return "cmd"

    # ── START ──────────────────────────────────────────────────────

    def start(self) -> TerminalInfo:
        """Start the Windows terminal session."""
        with self._lock:
            if self._state != TerminalState.IDLE:
                raise RuntimeError(
                    f"Cannot start session in state {self._state.value}"
                )
            self._state = TerminalState.STARTING
            self._stop_event.clear()
            self._output_buffer.clear()
            self._total_bytes = 0
            self._error = None
            self._start_time = time.time()

        if self.visible:
            self._start_visible()
        else:
            self._start_conpty()

        return self._build_info()

    def _start_visible(self) -> None:
        """
        Launch a visible PowerShell/CMD window with transcript recording.

        PowerShell Start-Transcript records everything to a file.
        We tail the file for real-time streaming.
        """
        import subprocess
        import datetime as _dt

        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            log_path = str(self.log_file)
        else:
            data_dir = Path(__file__).resolve().parents[3] / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            log_path = str(data_dir / f".vura_session_{self.session_id}.log")

        if self.shell in ("pwsh", "powershell"):
            cmd = (
                f"Start-Transcript -Path '{log_path}' -Append; "
                "Write-Host '[VURA Ghost Monitor] Recording... Type exit when done.' "
                "-ForegroundColor Green; "
                "& $env:COMSPEC; "
                "Stop-Transcript"
            )
            args = [self.shell, "-NoExit", "-Command", cmd]
        elif self.shell == "wt":
            # Windows Terminal — launch pwsh with transcript
            cmd = (
                f"Start-Transcript -Path '{log_path}' -Append; "
                "Write-Host '[VURA Ghost Monitor] Recording...' -ForegroundColor Green; "
                "& $env:COMSPEC; "
                "Stop-Transcript"
            )
            args = ["wt", "powershell", "-NoExit", "-Command", cmd]
        else:
            # cmd.exe — no built-in transcript, use basic approach
            args = ["cmd", "/k", "echo [VURA Ghost Monitor] Recording... Type exit to close."]

        try:
            self._process = subprocess.Popen(
                args,
                creationflags=subprocess.CREATE_NEW_CONSOLE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            with self._lock:
                self._backend = "transcript"
                self._state = TerminalState.RUNNING

            # Tail the transcript log for real-time streaming
            if self.shell != "cmd":
                log_path_obj = Path(log_path)
                self._reader_thread = threading.Thread(
                    target=self._tail_log_file,
                    args=(log_path_obj,),
                    daemon=True,
                    name=f"vura-win-{self.session_id}",
                )
                self._reader_thread.start()

        except FileNotFoundError as e:
            with self._lock:
                self._state = TerminalState.ERROR
                self._error = f"Shell not found: {e}"

    def _start_conpty(self) -> None:
        """
        Start a headless ConPTY session.

        Tries pywinpty first, then ctypes-based ConPTY.
        """
        # Try pywinpty
        try:
            import winpty  # type: ignore[import-not-found]
            self._pty = winpty.Winpty(
                cols=120,
                rows=30,
            )
            self._process = self._pty.spawn(self.shell)
            with self._lock:
                self._backend = "pywinpty"
                self._state = TerminalState.RUNNING

            self._reader_thread = threading.Thread(
                target=self._read_pywinpty_loop,
                daemon=True,
                name=f"vura-conpty-{self.session_id}",
            )
            self._reader_thread.start()
            return
        except ImportError:
            pass
        except Exception:
            pass

        # Try ctypes-based ConPTY
        try:
            self._start_conpty_ctypes()
            return
        except Exception:
            pass

        # Fallback to PowerShell transcript (headless)
        self._start_transcript_headless()

    def _start_conpty_ctypes(self) -> None:
        """
        Direct ConPTY via ctypes — no external dependencies.

        Requires Windows 10 1809+ (build 17763+).
        """
        import ctypes
        import subprocess

        kernel32 = ctypes.windll.kernel32

        # Check if CreatePseudoConsole is available
        if not hasattr(kernel32, "CreatePseudoConsole"):
            raise OSError("ConPTY not available on this Windows version")

        # Create pipes for ConPTY
        import ctypes.wintypes

        # For now, fall back to transcript — full ctypes ConPTY
        # requires complex pipe setup and is error-prone.
        # pywinpty is the recommended approach.
        raise OSError("ctypes ConPTY not implemented — use pywinpty")

    def _start_transcript_headless(self) -> None:
        """Headless PowerShell transcript recording."""
        import subprocess
        import datetime as _dt

        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            log_path = str(self.log_file)
        else:
            data_dir = Path(__file__).resolve().parents[3] / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            log_path = str(data_dir / f".vura_session_{self.session_id}.log")

        ps_cmd = (
            f"Start-Transcript -Path '{log_path}'; "
            "cmd; "
            "Stop-Transcript"
        )

        self._process = subprocess.Popen(
            ["powershell", "-NoExit", "-Command", ps_cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        with self._lock:
            self._backend = "transcript"
            self._state = TerminalState.RUNNING

        self._reader_thread = threading.Thread(
            target=self._tail_log_file,
            args=(Path(log_path),),
            daemon=True,
            name=f"vura-win-hl-{self.session_id}",
        )
        self._reader_thread.start()

    # ── READER LOOPS ───────────────────────────────────────────────

    def _read_pywinpty_loop(self) -> None:
        """Read from pywinpty agent."""
        while not self._stop_event.is_set():
            try:
                data = self._pty.read()
                if data:
                    raw = data.encode("utf-8") if isinstance(data, str) else data
                    self._process_chunk(raw)
                else:
                    time.sleep(DEFAULT_STREAM_INTERVAL)
            except Exception:
                break

        with self._lock:
            if self._state == TerminalState.RUNNING:
                self._state = TerminalState.STOPPED

    def _tail_log_file(self, log_path: Path) -> None:
        """Tail the transcript log file."""
        if not log_path.exists():
            return

        try:
            with open(log_path, "rb") as f:
                f.seek(0, 2)  # Seek to end

                while not self._stop_event.is_set():
                    data = f.read(DEFAULT_READ_BUFFER)
                    if data:
                        self._process_chunk(data)
                    else:
                        time.sleep(DEFAULT_STREAM_INTERVAL)
        except Exception:
            pass

    def _process_chunk(self, data: bytes) -> None:
        """Process a chunk of terminal data."""
        if not data:
            return

        with self._lock:
            self._output_buffer.append(data)
            self._total_bytes += len(data)

        # Write to log file
        if self.log_file:
            try:
                with open(self.log_file, "ab") as f:
                    f.write(data)
            except OSError:
                pass

        # Real-time callback
        if self.on_output and self.stream_mode == "realtime":
            text = strip_ansi(data)
            try:
                self.on_output(TerminalOutput(raw=data, text=text))
            except Exception:
                pass

    # ── STREAM ─────────────────────────────────────────────────────

    def stream(self) -> Iterator[TerminalOutput]:
        """Generator yielding TerminalOutput chunks."""
        last_count = 0

        while self.is_active:
            with self._lock:
                current_count = len(self._output_buffer)
                if current_count > last_count:
                    chunk = b"".join(self._output_buffer[last_count:current_count])
                    last_count = current_count
                    yield TerminalOutput(
                        raw=chunk,
                        text=strip_ansi(chunk),
                    )

            if last_count == 0:
                time.sleep(DEFAULT_STREAM_INTERVAL)

        # Yield remaining
        with self._lock:
            if len(self._output_buffer) > last_count:
                chunk = b"".join(self._output_buffer[last_count:])
                yield TerminalOutput(
                    raw=chunk,
                    text=strip_ansi(chunk),
                )

    # ── STOP ───────────────────────────────────────────────────────

    def stop(self) -> str:
        """Stop session and return cleaned text."""
        with self._lock:
            if self._state in (TerminalState.STOPPED, TerminalState.IDLE, TerminalState.ERROR):
                return self._get_all_text()
            self._state = TerminalState.STOPPING

        self._stop_event.set()

        # Kill process
        self._kill_process()

        # Wait for reader
        if self._reader_thread and self._reader_thread.is_alive():
            self._reader_thread.join(timeout=3.0)

        with self._lock:
            self._state = TerminalState.STOPPED

        return self._get_all_text()

    def discard(self) -> None:
        """Stop and discard all data."""
        self.stop()
        with self._lock:
            self._output_buffer.clear()
            self._total_bytes = 0
        if self.log_file and self.log_file.exists():
            try:
                self.log_file.unlink()
            except OSError:
                pass

    def _kill_process(self) -> None:
        """Terminate the child process."""
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=3)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None

        if self._pty:
            try:
                self._pty.close()
            except Exception:
                pass
            self._pty = None

    def _get_all_text(self) -> str:
        """Get all captured text, ANSI stripped."""
        with self._lock:
            all_data = b"".join(self._output_buffer)

        if self.log_file and self.log_file.exists():
            try:
                file_data = self.log_file.read_bytes()
                if len(file_data) > len(all_data):
                    all_data = file_data
            except OSError:
                pass

        return strip_ansi(all_data)

    # ── INFO ───────────────────────────────────────────────────────

    def get_info(self) -> TerminalInfo:
        """Get current session metadata."""
        import datetime as _dt
        start_dt = _dt.datetime.fromtimestamp(self._start_time) if self._start_time else None
        pid = None
        if self._process:
            pid = getattr(self._process, "pid", None)
        return TerminalInfo(
            session_id=self.session_id,
            pid=pid,
            shell=self.shell,
            start_time=start_dt,
            bytes_captured=self._total_bytes,
            state=self.state,
            log_file=self.log_file,
            error=self._error,
        )


# ══════════════════════════════════════════════════════════════════════
# FACTORY
# ══════════════════════════════════════════════════════════════════════

def create_win_session(
    session_id: str,
    shell: Optional[str] = None,
    log_file: Optional[Path] = None,
    visible: bool = True,
    **kwargs: Any,
) -> WinConptySession:
    """
    Factory for Windows terminal sessions.
    """
    return WinConptySession(
        session_id=session_id,
        shell=shell,
        log_file=log_file,
        visible=visible,
        **kwargs,
    )
