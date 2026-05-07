"""
VURA GUI — Home Page
═══════════════════════════════════
Dashboard with system status, stats, and quick actions.
"""

from __future__ import annotations

import glob
from pathlib import Path

import flet as ft

from gui.pages.base import BasePage, AppState
from gui.theme import C


class HomePage(BasePage):
    """Home dashboard page."""

    def __init__(self, state: AppState, page: ft.Page):
        super().__init__(state, page)

    def build(self) -> ft.Control:
        items: list[ft.Control] = []

        # License badge
        items.append(ft.Row([
            ft.Icon(ft.Icons.VERIFIED_USER, color=C.G, size=18),
            ft.Text("License:", color=C.DM, size=13),
            ft.Text("Free & Open Source", color=C.G, size=13, weight=ft.FontWeight.BOLD),
        ], spacing=6))

        # AI Engine status
        try:
            from app.utils.config import get_config_summary, validate_config
            sm = get_config_summary()
            er = validate_config()
            ok = not er
            cl = C.G if ok else C.R
            al = f"{sm['provider']}/{sm['model_name']}" if ok else self.t("nocfg")
            items.append(ft.Row([
                ft.Icon(ft.Icons.SMART_TOY, color=cl, size=18),
                ft.Text(self.t("ai"), color=C.DM, size=13),
                ft.Text(al, color=cl, size=13, weight=ft.FontWeight.BOLD),
            ], spacing=6))
        except Exception:
            items.append(ft.Text(f"{self.t('ai')} {self.t('uchk')}", color=C.O, size=13))

        # Report count
        rc = 0
        try:
            for ext in ["md", "json", "pdf", "docx"]:
                rc += len(glob.glob(str(self.state.root / "reports" / ext / f"*.{ext}")))
        except Exception:
            pass

        # Session status
        sa = self.state.ghost_engine.is_active()
        sl = self.t("rec") if sa else self.t("nosess")

        return ft.Column([
            # Title section
            ft.Container(
                content=ft.Column([
                    ft.Text("VURA", size=52, weight=ft.FontWeight.BOLD, color=C.T),
                    ft.Text(self.t("sub"), size=16, color=C.DM, italic=True),
                    ft.Text("v1.0.0", size=12, color=C.DM),
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=2),
                alignment=ft.Alignment(0, 0),
                padding=ft.Padding.only(top=30, bottom=10),
            ),

            # Stats cards
            ft.Row([
                self._card([ft.Row([
                    ft.Icon(ft.Icons.DESCRIPTION, color=C.T, size=28),
                    ft.Column([
                        ft.Text(str(rc), size=28, weight=ft.FontWeight.BOLD, color=C.W),
                        ft.Text(self.t("reps"), size=12, color=C.DM),
                    ], spacing=0),
                ], spacing=12)], width=200),
                self._card([ft.Row([
                    ft.Icon(ft.Icons.FIBER_MANUAL_RECORD, color=C.G if sa else C.DM, size=28),
                    ft.Column([
                        ft.Text(self.t("actv") if sa else self.t("idle"), size=20,
                                weight=ft.FontWeight.BOLD, color=C.G if sa else C.DM),
                        ft.Text(sl, size=12, color=C.DM),
                    ], spacing=0),
                ], spacing=12)], width=280),
            ], spacing=16, alignment=ft.MainAxisAlignment.CENTER),

            ft.Container(height=10),

            # System status card
            self._card(items, title=self.t("syst")),

            ft.Container(height=10),

            # Quick actions
            self._section(self.t("qact"), ft.Icons.FLASH_ON),
            ft.Row([
                self._btn(self.t("monitor"), ft.Icons.RADIO_BUTTON_CHECKED,
                          lambda _: self._nav(1), C.T, 180),
                self._btn(self.t("analyze"), ft.Icons.ANALYTICS,
                          lambda _: self._nav(2), C.T2, 180),
                self._btn(self.t("recon"), ft.Icons.RADAR,
                          lambda _: self._nav(3), C.CD, 180),
                self._btn(self.t("reports"), ft.Icons.FOLDER_OPEN,
                          lambda _: self._nav(4), C.S2, 180),
            ], spacing=12, alignment=ft.MainAxisAlignment.CENTER, wrap=True),
        ], scroll=ft.ScrollMode.AUTO, spacing=12,
           horizontal_alignment=ft.CrossAxisAlignment.CENTER)

    def _nav(self, idx: int):
        """Navigate to a page — set by main.py after construction."""
        pass
