"""
VURA Terminal Monitoring — PTY-based Session Management
═════════════════════════════════════════════════════════
Replaces the old script/cat-based approach with true PTY control.

Public API:
    from app.core.terminal import (
        TerminalSession,       # Unified session manager
        HookAllEngine,         # Multi-terminal reader
        TerminalState,         # Session state enum
        TerminalOutput,        # Output chunk dataclass
        TerminalInfo,          # Session metadata
        TerminalDescriptor,    # Discovered terminal info
        start_session,         # Quick-start helper
        strip_ansi,            # ANSI cleaning utility
    )

Example — Ghost Monitor:
    session = TerminalSession(session_id="scan_001", visible=True)
    session.start()
    # ... user works in the terminal ...
    clean_data = session.stop()

Example — HookAll:
    from app.core.terminal import HookAllEngine
    engine = HookAllEngine()
    terminals = engine.discover()
    result = engine.read_all()
    print(result.aggregated_text)
"""

from .session import TerminalSession, start_session, get_platform
from .hookall import (
    HookAllEngine,
    TerminalDiscovery,
    ExclusionManager,
    discover_terminals,
    read_all_terminals,
    exclude_terminal,
    get_excluded_terminals,
    get_hookall,
)
from .types import (
    TerminalState,
    TerminalOutput,
    TerminalInfo,
    TerminalDescriptor,
    HookAllResult,
    PlatformType,
    StreamMode,
)
from .unix_pty import strip_ansi, strip_ansi_str

__all__ = [
    # Session
    "TerminalSession",
    "start_session",
    "get_platform",
    # HookAll
    "HookAllEngine",
    "TerminalDiscovery",
    "ExclusionManager",
    "discover_terminals",
    "read_all_terminals",
    "exclude_terminal",
    "get_excluded_terminals",
    "get_hookall",
    # Types
    "TerminalState",
    "TerminalOutput",
    "TerminalInfo",
    "TerminalDescriptor",
    "HookAllResult",
    "PlatformType",
    "StreamMode",
    # Utilities
    "strip_ansi",
    "strip_ansi_str",
]
