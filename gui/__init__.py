"""
VURA GUI — Desktop Application Package
═══════════════════════════════════════════
Modular Flet-based GUI for VURA Vulnerability Reporting AI.

Quick start:
    python run_gui.py
    flet run gui/main.py
"""

from gui.main import main
from gui.theme import C
from gui.i18n import LangManager, L
from gui.pages.base import AppState
from gui.engine import GhostEngine

__all__ = ["main", "C", "LangManager", "L", "AppState", "GhostEngine"]
