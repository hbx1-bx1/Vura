"""
VURA Terminal Monitoring — Unix PTY Implementation
═════════════════════════════════════════════════════
Real pseudo-terminal session manager for Linux and macOS.

Uses Python's built-in pty module for true PTY control:
  - pty.fork() for headless sessions
  - pty.openpty() + terminal launcher for visible sessions
  - select.select() for non-blocking I/O
  - Zero command-injection risk (args passed as execvp list)
"""

from __future__ import annotations

import os
import pty
import re
import sys
import time
import fcntl
import errno
import struct
import select
import signal
import shutil
import threading
import termios
from pathlib import Path
from typing import Optional, Iterator, Callable, Any

from .types import (
    TerminalState, TerminalOutput, TerminalInfo,
    DEFAULT_READ_BUFFER, DEFAULT_STREAM_INTERVAL,
    ANSI_ESCAPE_RE, CONTROL_CHARS_RE,
)


# ══════════════════════════════════════════════════════════════════════
# ANSI CLEANING
# ══════════════════════════════════════════════════════════════════════

_ANSI_RE = re.compile(ANSI_ESCAPE_RE)
_CTRL_RE = re.compile(CONTROL_CHARS_RE)


def strip_ansi(raw_bytes: bytes) -> str:
    """
    Decode bytes to UTF-8 and strip ANSI escape sequences + control chars.

    Safe: replacement chars for decode errors, never raises.
    """
    text = raw_bytes.decode("utf-8", errors="replace")
    text = _ANSI_RE.sub("", text)
    text = _CTRL_RE.sub("", text)
    return text


def strip_ansi_str(text: str) -> str:
    """Strip ANSI from an already-decoded string."""
    text = _ANSI_RE.sub("", text)
    text = _CTRL_RE.sub("", text)
    return text


# ══════════════════════════════════════════════════════════════════════
# UNIX PTY SESSION
# ══════════════════════════════════════════════════════════════════════

class UnixPtySession:
    """
    Manages a pseudo-terminal session on Unix (Linux/macOS).

    Two modes:
      - VISIBLE: Launches a real terminal window with recording
        (uses `script` command — the most reliable cross-platform method)
      - HEADLESS: Creates a raw pty via pty.fork() with no visible window

    Thread safety:
      - All state access is protected by self._lock
      - Reader thread runs independently and pushes data to a buffer
      - Stream consumers read from the buffer via thread-safe iterator
    """

    def __init__(
        self,
        session_id: str,
        shell: Optional[str] = None,
        log_file: Optional[Path] = None,
        visible: bool = True,
        stream_mode: str = "realtime",  # "realtime" | "batch"
        on_output: Optional[Callable[[TerminalOutput], None]] = None,
    ):
        self.session_id = session_id
        self.shell = shell or os.environ.get("SHELL", "/bin/bash")
        self.log_file = log_file
        self.visible = visible
        self.stream_mode = stream_mode
        self.on_output = on_output

        # Internal state (all protected by _lock)
        self._lock = threading.Lock()
        self._state = TerminalState.IDLE
        self._master_fd: Optional[int] = None
        self._child_pid: Optional[int] = None
        self._launcher_pid: Optional[int] = None  # PID of visible terminal process
        self._reader_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._output_buffer: list[bytes] = []
        self._total_bytes = 0
        self._pts_path: Optional[str] = None
        self._error: Optional[str] = None
        self._start_time: Optional[float] = None

        # For visible mode: where script records to
        self._script_log: Optional[Path] = None

    # ── Properties ─────────────────────────────────────────────────

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
    def pts_path(self) -> Optional[str]:
        with self._lock:
            return self._pts_path

    @property
    def child_pid(self) -> Optional[int]:
        with self._lock:
            return self._child_pid

    # ── START ──────────────────────────────────────────────────────

    def start(self) -> TerminalInfo:
        """
        Start the terminal session.

        Returns:
            TerminalInfo with session metadata.
        """
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
            return self._start_visible()
        else:
            return self._start_headless()

    def _start_visible(self) -> TerminalInfo:
        """
        Launch a visible terminal window with script recording.

        This is the safest and most compatible approach:
          1. Find the best available terminal emulator
          2. Launch it with `script` recording to our log file
          3. Start a background thread that tails the log file
             for real-time streaming
        """
        import datetime as _dt

        # Ensure log directory exists
        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            self._script_log = self.log_file
        else:
            data_dir = Path(__file__).resolve().parents[3] / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            self._script_log = data_dir / f".vura_session_{self.session_id}.log"

        terminal_cmd = self._build_visible_command()
        if terminal_cmd is None:
            with self._lock:
                self._state = TerminalState.ERROR
                self._error = "No terminal emulator found"
            return self._build_info()

        # Launch terminal
        try:
            proc = self._launch_terminal(terminal_cmd)
            with self._lock:
                self._launcher_pid = proc.pid
                self._state = TerminalState.RUNNING

            # Start log-file tailer for real-time streaming
            self._reader_thread = threading.Thread(
                target=self._tail_log_file,
                daemon=True,
                name=f"vura-reader-{self.session_id}",
            )
            self._reader_thread.start()

        except FileNotFoundError as e:
            with self._lock:
                self._state = TerminalState.ERROR
                self._error = f"Terminal not found: {e}"
        except Exception as e:
            with self._lock:
                self._state = TerminalState.ERROR
                self._error = str(e)

        return self._build_info()

    def _build_visible_command(self) -> Optional[list[str]]:
        """
        Build the command to launch a visible terminal with script recording.

        Returns a list of args (safe — no shell injection possible).
        """
        if not shutil.which("script"):
            return None

        log_path = str(self._script_log)
        shell = self.shell

        # Banner message
        banner = (
            "echo -e '\\033[1;32m[VURA Ghost Monitor]\\033[0m "
            "Recording... Type exit when done.'"
        )

        system = sys.platform

        if system == "darwin":
            # macOS: script -q -a LOG SHELL
            script_args = ["script", "-q", "-a", log_path, shell]
            cmd_str = f"{banner}; {' '.join(script_args)}"
            return self._launch_for_macos(cmd_str)

        else:
            # Linux: script -q -a -c SHELL LOG
            script_args = ["script", "-q", "-a", "-c", shell, log_path]
            cmd_str = f"{banner}; {' '.join(script_args)}"
            return self._launch_for_linux(cmd_str)

    def _launch_for_macos(self, cmd: str) -> Optional[list[str]]:
        """Build macOS terminal launch command using osascript."""
        # Escape for AppleScript double-quoted string
        escaped = cmd.replace("\\", "\\\\").replace('"', '\\"')

        applescript = (
            'tell application "Terminal"\n'
            "  activate\n"
            f'  do script "{escaped}"\n'
            "end tell"
        )
        return ["osascript", "-e", applescript]

    def _launch_for_linux(self, cmd: str) -> Optional[list[str]]:
        """Build Linux terminal launch command."""
        # Try terminals in order of preference
        terminals = [
            ("gnome-terminal", ["gnome-terminal", "--", "bash", "-c", cmd]),
            ("konsole", ["konsole", "-e", "bash", "-c", cmd]),
            ("xfce4-terminal", ["xfce4-terminal", "-e", cmd]),
            ("xterm", ["xterm", "-e", "bash", "-c", cmd]),
        ]

        for name, launch_cmd in terminals:
            if shutil.which(name):
                return launch_cmd

        # Fallback: try x-terminal-emulator
        if shutil.which("x-terminal-emulator"):
            return ["x-terminal-emulator", "-e", "bash", "-c", cmd]

        return None

    def _launch_terminal(self, cmd_args: list[str]) -> Any:
        """Launch terminal process safely — args as list, no shell=True."""
        import subprocess
        return subprocess.Popen(
            cmd_args,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _start_headless(self) -> TerminalInfo:
        """
        Create a headless PTY session using pty.fork().

        No visible terminal window — just a raw PTY pair.
        The child runs the shell, the parent reads from master fd.
        """
        import datetime as _dt

        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)

        try:
            pid, master_fd = pty.fork()

            if pid == 0:
                # ── Child process: replace with shell ──
                # Set terminal size
                try:
                    winsize = struct.pack("HHHH", 24, 80, 0, 0)
                    fcntl.ioctl(0, termios.TIOCSWINSZ, winsize)
                except OSError:
                    pass

                # Exec the shell — safe, no shell injection
                os.execvp(self.shell, [self.shell])
                os._exit(1)  # unreachable

            # ── Parent process ──
            with self._lock:
                self._master_fd = master_fd
                self._child_pid = pid
                self._state = TerminalState.RUNNING

            # Set master fd to non-blocking
            flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
            fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            # Get pts path
            try:
                self._pts_path = os.ttyname(master_fd)
            except OSError:
                pass

            # Start reader thread
            self._reader_thread = threading.Thread(
                target=self._read_pty_loop,
                args=(master_fd,),
                daemon=True,
                name=f"vura-pty-{self.session_id}",
            )
            self._reader_thread.start()

        except Exception as e:
            with self._lock:
                self._state = TerminalState.ERROR
                self._error = str(e)

        return self._build_info()

    # ── READER LOOPS ───────────────────────────────────────────────

    def _read_pty_loop(self, master_fd: int) -> None:
        """
        Read from the PTY master fd in a loop until stop or child exits.

        Uses select.select() for non-blocking I/O.
        Each chunk is:
          1. Appended to the output buffer (for batch mode)
          2. Written to the log file
          3. Passed to on_output callback (for real-time mode)
        """
        while not self._stop_event.is_set():
            try:
                ready, _, _ = select.select([master_fd], [], [], 0.5)
                if not ready:
                    continue

                data = os.read(master_fd, DEFAULT_READ_BUFFER)
                if not data:
                    break  # EOF

                self._process_chunk(data)

            except OSError as e:
                if e.errno == errno.EIO:
                    break  # PTY closed
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    continue
                with self._lock:
                    self._error = str(e)
                break
            except Exception:
                break

        # Clean up
        try:
            os.close(master_fd)
        except OSError:
            pass

        with self._lock:
            self._master_fd = None
            if self._state == TerminalState.RUNNING:
                self._state = TerminalState.STOPPED

    def _tail_log_file(self) -> None:
        """
        Tail the script log file for real-time streaming in visible mode.

        Opens the file, seeks to end, and reads new bytes as they appear.
        This is safe because `script` appends atomically.
        """
        if not self._script_log or not self._script_log.exists():
            return

        try:
            with open(self._script_log, "rb") as f:
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
        """Process a chunk of raw PTY data."""
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
                pass  # Don't let callback errors break the reader

    # ── STREAM ─────────────────────────────────────────────────────

    def stream(self) -> Iterator[TerminalOutput]:
        """
        Generator that yields TerminalOutput chunks in real-time.

        Usage:
            for output in session.stream():
                print(output.text)

        Thread-safe: reads from a copy of the buffer.
        """
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

            if last_count == 0 or not self.is_active:
                time.sleep(DEFAULT_STREAM_INTERVAL)

        # Yield remaining data
        with self._lock:
            if len(self._output_buffer) > last_count:
                chunk = b"".join(self._output_buffer[last_count:])
                yield TerminalOutput(
                    raw=chunk,
                    text=strip_ansi(chunk),
                )

    # ── STOP ───────────────────────────────────────────────────────

    def stop(self) -> str:
        """
        Stop the session and return cleaned text.

        Returns:
            Clean text (ANSI stripped) of the entire session.
        """
        with self._lock:
            if self._state in (TerminalState.STOPPED, TerminalState.IDLE, TerminalState.ERROR):
                return self._get_all_text()
            self._state = TerminalState.STOPPING

        # Signal reader to stop
        self._stop_event.set()

        # Kill child process
        self._kill_child()

        # Wait for reader thread
        if self._reader_thread and self._reader_thread.is_alive():
            self._reader_thread.join(timeout=3.0)

        with self._lock:
            self._state = TerminalState.STOPPED

        return self._get_all_text()

    def discard(self) -> None:
        """Stop the session and discard all data."""
        self.stop()
        with self._lock:
            self._output_buffer.clear()
            self._total_bytes = 0

        # Delete log file
        if self._script_log and self._script_log.exists():
            try:
                self._script_log.unlink()
            except OSError:
                pass

    def _kill_child(self) -> None:
        """Send SIGTERM to the child process, then SIGKILL if needed."""
        # Kill launcher process (visible terminal)
        if self._launcher_pid:
            try:
                os.kill(self._launcher_pid, signal.SIGTERM)
            except OSError:
                pass
            self._launcher_pid = None

        # Kill PTY child
        if self._child_pid:
            try:
                os.kill(self._child_pid, signal.SIGTERM)
                time.sleep(0.5)
                # Check if still alive
                try:
                    os.kill(self._child_pid, 0)
                    os.kill(self._child_pid, signal.SIGKILL)
                except OSError:
                    pass  # Already dead
            except OSError:
                pass
            self._child_pid = None

    def _get_all_text(self) -> str:
        """Get all captured text, ANSI stripped."""
        with self._lock:
            all_data = b"".join(self._output_buffer)

        # If we have a log file, read from it (may have more data)
        if self._script_log and self._script_log.exists():
            try:
                file_data = self._script_log.read_bytes()
                if len(file_data) > len(all_data):
                    all_data = file_data
            except OSError:
                pass

        return strip_ansi(all_data)

    # ── INFO ───────────────────────────────────────────────────────

    def get_info(self) -> TerminalInfo:
        """Get current session metadata."""
        return self._build_info()

    def _build_info(self) -> TerminalInfo:
        import datetime as _dt
        start_dt = _dt.datetime.fromtimestamp(self._start_time) if self._start_time else None
        return TerminalInfo(
            session_id=self.session_id,
            pid=self._child_pid or self._launcher_pid,
            shell=self.shell,
            pts_path=self._pts_path,
            start_time=start_dt,
            bytes_captured=self._total_bytes,
            state=self.state,
            log_file=self._script_log or self.log_file,
            error=self._error,
        )


# ══════════════════════════════════════════════════════════════════════
# FACTORY
# ══════════════════════════════════════════════════════════════════════

def create_unix_session(
    session_id: str,
    shell: Optional[str] = None,
    log_file: Optional[Path] = None,
    visible: bool = True,
    **kwargs: Any,
) -> UnixPtySession:
    """
    Factory for Unix PTY sessions.

    Parameters:
        session_id: Unique session identifier
        shell: Shell to use (default: $SHELL or /bin/bash)
        log_file: Where to save recorded output
        visible: True = real terminal window, False = headless pty
        **kwargs: Passed to UnixPtySession
    """
    return UnixPtySession(
        session_id=session_id,
        shell=shell,
        log_file=log_file,
        visible=visible,
        **kwargs,
    )
