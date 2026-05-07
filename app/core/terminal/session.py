"""
VURA Terminal Monitoring — Unified Session Manager
═════════════════════════════════════════════════════
Single entry point for terminal session management.

Automatically selects the correct backend:
  - Linux/macOS → UnixPtySession (pty.fork / script)
  - Windows     → WinConptySession (ConPTY / transcript)

Usage:
    from app.core.terminal import TerminalSession

    # Start recording
    session = TerminalSession(session_id="scan_001", visible=True)
    session.start()

    # Real-time streaming
    for output in session.stream():
        print(output.text)

    # Stop and get clean data
    clean_text = session.stop()
"""

from __future__ import annotations

import os
import sys
import uuid
import datetime
from pathlib import Path
from typing import Optional, Iterator, Callable, Any

from .types import (
    TerminalState, TerminalOutput, TerminalInfo,
    PlatformType, StreamMode,
)


# ══════════════════════════════════════════════════════════════════════
# PLATFORM DETECTION
# ══════════════════════════════════════════════════════════════════════

def _detect_platform() -> PlatformType:
    """Detect the current OS platform."""
    if sys.platform.startswith("win"):
        return PlatformType.WINDOWS
    elif sys.platform == "darwin":
        return PlatformType.MACOS
    else:
        return PlatformType.LINUX


# ══════════════════════════════════════════════════════════════════════
# TERMINAL SESSION — UNIFIED FACADE
# ══════════════════════════════════════════════════════════════════════

class TerminalSession:
    """
    Unified terminal session manager.

    Wraps the platform-specific backend (UnixPtySession or WinConptySession)
    behind a single consistent API.

    Parameters:
        session_id: Unique identifier (auto-generated if None)
        shell: Shell executable to use (auto-detected if None)
        log_file: Path to save recorded output
        visible: True = real terminal window, False = headless
        stream_mode: "realtime" or "batch"
        on_output: Callback called for each output chunk (realtime mode)

    Example:
        >>> session = TerminalSession(visible=True)
        >>> session.start()
        >>> # User works in the terminal...
        >>> clean_text = session.stop()
        >>> print(f"Captured {len(clean_text)} chars")
    """

    def __init__(
        self,
        session_id: Optional[str] = None,
        shell: Optional[str] = None,
        log_file: Optional[Path] = None,
        visible: bool = True,
        stream_mode: str = "realtime",
        on_output: Optional[Callable[[TerminalOutput], None]] = None,
    ):
        self.session_id = session_id or f"vura_{uuid.uuid4().hex[:8]}"
        self._platform = _detect_platform()
        self._backend: Any = None  # UnixPtySession or WinConptySession

        # Build the appropriate backend
        if self._platform == PlatformType.WINDOWS:
            from .win_conpty import WinConptySession
            self._backend = WinConptySession(
                session_id=self.session_id,
                shell=shell,
                log_file=log_file,
                visible=visible,
                stream_mode=stream_mode,
                on_output=on_output,
            )
        else:
            from .unix_pty import UnixPtySession
            self._backend = UnixPtySession(
                session_id=self.session_id,
                shell=shell,
                log_file=log_file,
                visible=visible,
                stream_mode=stream_mode,
                on_output=on_output,
            )

    # ── Properties ─────────────────────────────────────────────────

    @property
    def state(self) -> TerminalState:
        return self._backend.state

    @property
    def is_active(self) -> bool:
        return self._backend.is_active

    @property
    def total_bytes(self) -> int:
        return self._backend.total_bytes

    @property
    def platform(self) -> PlatformType:
        return self._platform

    # ── Lifecycle ──────────────────────────────────────────────────

    def start(self) -> TerminalInfo:
        """
        Start the terminal session.

        Visible mode: opens a real terminal window for the user to work in.
        Headless mode: creates a hidden PTY session.

        Returns:
            TerminalInfo with session metadata.
        """
        return self._backend.start()

    def stop(self) -> str:
        """
        Stop the session and return cleaned text.

        Returns:
            All captured text with ANSI escape codes stripped.
        """
        return self._backend.stop()

    def discard(self) -> None:
        """Stop the session and discard all captured data."""
        self._backend.discard()

    # ── Streaming ──────────────────────────────────────────────────

    def stream(self) -> Iterator[TerminalOutput]:
        """
        Generator that yields TerminalOutput chunks in real-time.

        Usage:
            for output in session.stream():
                # Update GUI, log, or process commands
                print(output.text)

        The generator ends when the session stops.
        """
        yield from self._backend.stream()

    # ── Info ───────────────────────────────────────────────────────

    def get_info(self) -> TerminalInfo:
        """Get current session metadata."""
        return self._backend.get_info()

    # ── Context Manager ────────────────────────────────────────────

    def __enter__(self) -> TerminalSession:
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_type is not None:
            self.discard()
        else:
            self.stop()

    # ── Static Helpers ─────────────────────────────────────────────

    @staticmethod
    def clean_ansi(text: str) -> str:
        """Strip ANSI escape codes from text."""
        from .unix_pty import strip_ansi_str
        return strip_ansi_str(text)

    @staticmethod
    def clean_ansi_bytes(data: bytes) -> str:
        """Decode bytes and strip ANSI escape codes."""
        from .unix_pty import strip_ansi
        return strip_ansi(data)


# ══════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ══════════════════════════════════════════════════════════════════════

def start_session(
    visible: bool = True,
    log_file: Optional[Path] = None,
    **kwargs: Any,
) -> TerminalSession:
    """
    Quick start: create and start a terminal session.

    Usage:
        session = start_session(visible=True)
        # ... user works ...
        data = session.stop()
    """
    session = TerminalSession(visible=visible, log_file=log_file, **kwargs)
    session.start()
    return session


def get_platform() -> PlatformType:
    """Get the current platform type."""
    return _detect_platform()
