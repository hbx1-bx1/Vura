"""
VURA Terminal Monitoring — Type Definitions
════════════════════════════════════════════
Data classes, enums, and type aliases for the pty-based
terminal monitoring system.
"""

from __future__ import annotations

import os
import enum
import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ══════════════════════════════════════════════════════════════════════
# ENUMS
# ══════════════════════════════════════════════════════════════════════

class TerminalState(enum.Enum):
    """Lifecycle states of a monitored terminal session."""
    IDLE = "idle"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


class PlatformType(enum.Enum):
    """Supported OS platforms."""
    LINUX = "linux"
    MACOS = "darwin"
    WINDOWS = "windows"


class StreamMode(enum.Enum):
    """How output is consumed from a terminal session."""
    REALTIME = "realtime"       # Stream bytes as they arrive
    BATCH = "batch"             # Collect everything, read at stop


# ══════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ══════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class TerminalOutput:
    """
    A chunk of terminal output.

    Attributes:
        raw:      Raw bytes from the pty (includes ANSI escape codes)
        text:     Decoded text with ANSI codes stripped
        timestamp: When this chunk was captured
        is_command: True if this chunk appears to be a user command (not output)
    """
    raw: bytes
    text: str
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)
    is_command: bool = False

    @property
    def size(self) -> int:
        return len(self.raw)


@dataclass(frozen=True)
class TerminalInfo:
    """Metadata about an active or completed terminal session."""
    session_id: str
    pid: Optional[int] = None
    shell: str = ""
    pts_path: Optional[str] = None
    start_time: Optional[datetime.datetime] = None
    end_time: Optional[datetime.datetime] = None
    bytes_captured: int = 0
    state: TerminalState = TerminalState.IDLE
    log_file: Optional[Path] = None
    error: Optional[str] = None

    @property
    def duration(self) -> Optional[datetime.timedelta]:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        if self.start_time:
            return datetime.datetime.now() - self.start_time
        return None

    @property
    def is_active(self) -> bool:
        return self.state in (
            TerminalState.STARTING,
            TerminalState.RUNNING,
            TerminalState.PAUSED,
        )


@dataclass
class HookAllResult:
    """Result from a HookAll scan of multiple terminals."""
    success: bool
    terminals_found: int = 0
    terminals_read: int = 0
    total_bytes: int = 0
    aggregated_text: str = ""
    errors: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)


@dataclass
class TerminalDescriptor:
    """
    Describes an interactive terminal found on the system.

    Used by HookAll to present a list of targetable terminals.
    """
    pts_path: str          # /dev/pts/0, /dev/ttys000, WIN-PID-1234
    shell_name: str        # zsh, bash, powershell, cmd
    pid: int
    user: str = ""
    is_excluded: bool = False


# ══════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════

INTERACTIVE_SHELLS_UNIX = frozenset({
    "zsh", "bash", "sh", "fish", "tcsh", "csh", "dash", "ksh",
})

INTERACTIVE_SHELLS_WIN = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe",
})

DEFAULT_READ_BUFFER = 4096       # Bytes per select() read
DEFAULT_STREAM_INTERVAL = 0.05   # Seconds between stream yields
ANSI_ESCAPE_RE = r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
CONTROL_CHARS_RE = r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"
