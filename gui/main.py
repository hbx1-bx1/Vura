"""
VURA GUI — Main Application
═══════════════════════════════════
App bootstrap, NavigationRail routing, and page caching.
"""

from __future__ import annotations

import sys
from typing import Optional

import flet as ft

from gui.theme import C, WIN_WIDTH, WIN_HEIGHT, WIN_MIN_WIDTH, WIN_MIN_HEIGHT
from gui.i18n import LangManager
from gui.components.navigation import create_snack_bar
from gui.pages.base import AppState
from gui.pages import (
    HomePage, MonitorPage, AnalyzePage,
    ReconPage, ReportsPage, SettingsPage,
)


# ══════════════════════════════════════════════════════════════════════
# Page Builders
# ══════════════════════════════════════════════════════════════════════

_PAGE_BUILDERS = [
    HomePage,
    MonitorPage,
    AnalyzePage,
    ReconPage,
    ReportsPage,
    SettingsPage,
]

_NAV_LABELS = [
    "home", "monitor", "analyze", "recon", "reports", "settings",
]

_NAV_ICONS = [
    (ft.Icons.HOME_OUTLINED, ft.Icons.HOME),
    (ft.Icons.RADIO_BUTTON_UNCHECKED, ft.Icons.RADIO_BUTTON_CHECKED),
    (ft.Icons.ANALYTICS_OUTLINED, ft.Icons.ANALYTICS),
    (ft.Icons.RADAR_OUTLINED, ft.Icons.RADAR),
    (ft.Icons.FOLDER_OUTLINED, ft.Icons.FOLDER),
    (ft.Icons.SETTINGS_OUTLINED, ft.Icons.SETTINGS),
]


# ══════════════════════════════════════════════════════════════════════
# App Controller
# ══════════════════════════════════════════════════════════════════════

class VuraApp:
    """
    Main application controller.

    Manages navigation, page caching, snack bar, and shared state.
    """

    def __init__(self):
        self.state = AppState()
        self.page_cache: dict[int, ft.Control] = {}
        self._current_page: Optional[ft.Container] = None
        self._rail: Optional[ft.NavigationRail] = None
        self._snack_bar: Optional[ft.Container] = None
        self._snack_callback = None

    def __call__(self, page: ft.Page):
        """Flet app entry point."""
        self._page = page
        self._setup_page()
        self._build_layout()

    def _setup_page(self):
        """Configure the Flet page."""
        p = self._page
        p.title = "VURA \u2014 Vulnerability Reporting AI"
        p.bgcolor = C.BG
        p.padding = 0
        p.window.width = WIN_WIDTH
        p.window.height = WIN_HEIGHT
        p.window.min_width = WIN_MIN_WIDTH
        p.window.min_height = WIN_MIN_HEIGHT
        p.theme_mode = ft.ThemeMode.DARK

    def _build_layout(self):
        """Build the main layout with NavigationRail."""
        # Snack bar
        self._snack_bar, self._snack_callback = create_snack_bar()

        # Content area
        self._current_page = ft.Container(content=self._get_page(0), expand=True, padding=24)

        # Navigation Rail
        self._rail = ft.NavigationRail(
            selected_index=0,
            label_type=ft.NavigationRailLabelType.ALL,
            min_width=80,
            min_extended_width=200,
            bgcolor=C.N,
            indicator_color=C.T,
            on_change=lambda e: self._navigate(e.control.selected_index),
            destinations=self._build_nav_destinations(),
        )

        self._page.add(ft.Column([
            ft.Row([
                self._rail,
                ft.VerticalDivider(width=1, color=C.N3),
                self._current_page,
            ], expand=True, spacing=0),
            self._snack_bar,
        ], expand=True, spacing=0))

    def _build_nav_destinations(self) -> list[ft.NavigationRailDestination]:
        """Build NavigationRail destination items."""
        dests = []
        for icon_out, icon_sel in _NAV_ICONS:
            label_key = _NAV_LABELS[len(dests)]
            dests.append(ft.NavigationRailDestination(
                icon=icon_out,
                selected_icon=icon_sel,
                label=self.state.t(label_key),
            ))
        return dests

    def _get_page(self, idx: int) -> ft.Control:
        """Get or create a page instance."""
        if idx not in self.page_cache:
            page_cls = _PAGE_BUILDERS[idx]
            page_instance = page_cls(self.state, self._page)

            # Inject snack callback into page
            page_instance._show_snack = self._snack_callback

            # Inject nav callback for home page quick actions
            if idx == 0:
                page_instance._nav = self._navigate

            # Inject rebuild callbacks for settings page
            if idx == 5:
                page_instance._rebuild_nav_callback = self._rebuild_nav_labels
                page_instance._reload_callback = lambda: self._navigate(5)

            self.page_cache[idx] = page_instance.build()

        return self.page_cache[idx]

    def _navigate(self, idx: int):
        """Navigate to a page by index."""
        # Clear cache for dynamic pages (home, monitor, reports)
        if idx in (0, 1, 4):
            self.page_cache.pop(idx, None)

        self._current_page.content = self._get_page(idx)
        self._rail.selected_index = idx
        self._page.update()

    def _rebuild_nav_labels(self):
        """Update NavigationRail labels for language change."""
        for i, d in enumerate(self._rail.destinations):
            d.label = self.state.t(_NAV_LABELS[i])


# ══════════════════════════════════════════════════════════════════════
# Entry Point
# ══════════════════════════════════════════════════════════════════════

def main(page: ft.Page):
    """
    Legacy entry point — compatible with `ft.app(main)`.
    Delegates to VuraApp controller.
    """
    app = VuraApp()
    app(page)


if __name__ == "__main__":
    ft.app(main)
