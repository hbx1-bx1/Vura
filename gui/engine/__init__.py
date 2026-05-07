"""
VURA GUI — Engine
═══════════════════════════════════
Ghost Monitor & HookAll logic for the GUI.
Delegates to app.core.terminal (pty-based) internally.
"""

from .terminal import (
    GhostEngine,
    ghost_start,
    ghost_stop,
    ghost_discard,
    ghost_active,
    ghost_size,
    ghost_hookall,
    ghost_list_terminals,
    ghost_exclude_terminals,
    ghost_get_excluded,
)

__all__ = [
    "GhostEngine",
    "ghost_start",
    "ghost_stop",
    "ghost_discard",
    "ghost_active",
    "ghost_size",
    "ghost_hookall",
    "ghost_list_terminals",
    "ghost_exclude_terminals",
    "ghost_get_excluded",
]
