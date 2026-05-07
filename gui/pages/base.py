"""
VURA GUI — Page Base & Application State
════════════════════════════════════════════
Shared state and abstract base class for all pages.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

import flet as ft

from gui.theme import C
from gui.i18n import LangManager
from gui.engine import GhostEngine


# ══════════════════════════════════════════════════════════════════════
# Application State (Singleton)
# ══════════════════════════════════════════════════════════════════════

class AppState:
    """
    Shared application state accessible from all pages.

    This replaces the scattered global variables in the old gui.py.
    """

    def __init__(self):
        self.lang = LangManager(default="e")
        self.ghost_engine = GhostEngine()
        self.ghost_data: dict = {"raw": None}
        self._root = Path(__file__).resolve().parents[2]
        self._data_dir = self._root / "data"

    @property
    def root(self) -> Path:
        return self._root

    @property
    def data_dir(self) -> Path:
        return self._data_dir

    @property
    def log_file(self) -> Path:
        return self._data_dir / ".vura_session.log"

    def t(self, key: str) -> str:
        """Shorthand for translation."""
        return self.lang.t(key)


# ══════════════════════════════════════════════════════════════════════
# Base Page
# ══════════════════════════════════════════════════════════════════════

class BasePage(ABC):
    """
    Abstract base for all VURA pages.

    Subclasses must implement build() which returns the page content.
    """

    def __init__(self, state: AppState, page: ft.Page):
        self.state = state
        self.page = page
        self.t = state.lang.t

    @abstractmethod
    def build(self) -> ft.Control:
        """Build and return the page content."""
        ...

    def _card(self, content, title=None, width=None):
        """Shorthand for card component."""
        from gui.components.cards import card
        return card(content, title=title, width=width)

    def _btn(self, label, icon=None, on_click=None, color=None, width=None):
        """Shorthand for button component."""
        from gui.components.buttons import btn
        return btn(label, icon=icon, on_click=on_click, color=color, width=width)

    def _tf(self, label, value="", width=None, multiline=False, password=False,
            icon=None, read_only=False, lines=6):
        """Shorthand for text field component."""
        from gui.components.inputs import text_field
        return text_field(label, value=value, width=width, multiline=multiline,
                          password=password, icon=icon, read_only=read_only, lines=lines)

    def _dd(self, label, options, value, width=180):
        """Shorthand for dropdown component."""
        from gui.components.inputs import dropdown
        return dropdown(label, options, value, width=width)

    def _section(self, text, icon=None):
        """Shorthand for section header."""
        from gui.components.cards import section_header
        return section_header(text, icon=icon)

    def _run_bg(self, fn, cb=None):
        """Shorthand for background task runner."""
        from gui.components.navigation import run_bg
        run_bg(self.page, fn, cb)
