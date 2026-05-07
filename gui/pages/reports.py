"""
VURA GUI — Reports Page
═══════════════════════════════════
Reports archive browsing, preview, and recreation.
"""

from __future__ import annotations

import glob
import json
from pathlib import Path
from typing import Optional

import flet as ft

from gui.pages.base import BasePage, AppState
from gui.theme import C
from gui.components.buttons import btn
from gui.components.cards import card, section_header


class ReportsPage(BasePage):
    """Reports archive page."""

    _fmt_colors = {"MD": C.T, "PDF": C.R, "DOCX": C.CD, "JSON": C.O, "SH": C.S2}

    def __init__(self, state: AppState, page: ft.Page):
        super().__init__(state, page)
        self._sessions: dict = {}
        self._scol: Optional[ft.Column] = None
        self._vtitle: Optional[ft.Text] = None
        self._vcont: Optional[ft.TextField] = None
        self._ftabs: Optional[ft.Row] = None

    def build(self) -> ft.Control:
        self._scol = ft.Column(spacing=4, scroll=ft.ScrollMode.AUTO, expand=True)
        self._vtitle = ft.Text(self.t("selrep"), size=15, color=C.DM,
                                weight=ft.FontWeight.BOLD)
        self._vcont = self._tf("", read_only=True, multiline=True, lines=25)
        self._vcont.expand = True
        self._ftabs = ft.Row(spacing=6)

        self._load_reports()

        left = ft.Container(
            content=ft.Column([
                ft.Text(self.t("rlist"), size=14, weight=ft.FontWeight.BOLD, color=C.T),
                ft.Divider(height=1, color=C.N3),
                self._scol,
            ], spacing=6, expand=True),
            bgcolor=C.N2, border_radius=12, padding=12, width=340,
            border=ft.Border.all(1, C.N3), expand=True,
        )

        right = ft.Container(
            content=ft.Column([
                self._vtitle, self._ftabs,
                ft.Divider(height=1, color=C.N3),
                self._vcont,
            ], spacing=8, expand=True, scroll=ft.ScrollMode.AUTO),
            bgcolor=C.N2, border_radius=12, padding=16,
            border=ft.Border.all(1, C.N3), expand=2,
        )

        return ft.Column([
            section_header(self.t("arch"), ft.Icons.FOLDER_OPEN),
            ft.Row([
                btn(self.t("ref"), ft.Icons.REFRESH, self._on_refresh, C.T, 130),
                btn(self.t("opf"), ft.Icons.FOLDER, self._on_open_folder, C.CD, 150),
                btn(self.t("recreate"), ft.Icons.REPLAY, self._on_recreate, C.O, 220),
            ], spacing=10, wrap=True),
            ft.Container(height=6),
            ft.Row([left, right], spacing=12, expand=True),
        ], spacing=8, expand=True)

    def _load_reports(self):
        """Scan reports directory and build session list."""
        self._sessions.clear()
        self._scol.controls.clear()

        rr = self.state.root / "reports"
        files = []
        for ext in ["md", "json", "pdf", "docx", "sh"]:
            files.extend(glob.glob(str(rr / ext / f"*.{ext}")))

        if not files:
            self._scol.controls.append(
                ft.Text(self.t("norep"), color=C.DM, size=13)
            )
            return

        for p in files:
            nm = Path(p).stem
            ex = Path(p).suffix[1:].upper()
            if nm not in self._sessions:
                self._sessions[nm] = {"f": [], "p": {}}
            if ex not in self._sessions[nm]["f"]:
                self._sessions[nm]["f"].append(ex)
                self._sessions[nm]["p"][ex] = p

        self._scol.controls.append(
            ft.Text(self.t("sf").format(s=len(self._sessions), f=len(files)),
                    size=12, color=C.DM)
        )

        for sid in sorted(self._sessions.keys(), reverse=True):
            d = self._sessions[sid]
            badges = ft.Row([
                ft.Container(
                    content=ft.Text(f, size=9, color=C.W, weight=ft.FontWeight.W_600),
                    bgcolor=self._fmt_colors.get(f, C.N3),
                    border_radius=4,
                    padding=ft.Padding.symmetric(horizontal=6, vertical=1),
                ) for f in d["f"]
            ], spacing=3)

            dp = ""
            try:
                pts = sid.split("_")
                if len(pts) >= 3:
                    x = pts[-2]
                    dp = f"{x[:4]}-{x[4:6]}-{x[6:8]}"
            except Exception:
                pass

            self._scol.controls.append(
                ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Icon(ft.Icons.DESCRIPTION, color=C.T, size=14),
                            ft.Text(sid, size=11, color=C.W, expand=True,
                                    max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
                        ], spacing=6),
                        ft.Row([
                            ft.Text(dp, size=10, color=C.DM) if dp else ft.Container(),
                            badges,
                        ], spacing=6, alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    ], spacing=4),
                    bgcolor=C.N, border_radius=8,
                    padding=ft.Padding.symmetric(horizontal=10, vertical=8),
                    on_click=lambda e, s=sid: self._select(s),
                )
            )

    def _select(self, sid: str):
        """Select a session for viewing."""
        d = self._sessions.get(sid, {})
        fmts = d.get("f", [])
        paths = d.get("p", {})

        self._ftabs.controls.clear()
        for f in fmts:
            fc = self._fmt_colors.get(f, C.N3)
            self._ftabs.controls.append(
                ft.Container(
                    content=ft.Text(f, size=12, color=C.W,
                                    weight=ft.FontWeight.W_600),
                    bgcolor=fc, border_radius=6,
                    padding=ft.Padding.symmetric(horizontal=14, vertical=6),
                    on_click=lambda e, ff=f, pp=paths.get(f, ""):
                        self._load_content(sid, ff, pp),
                )
            )

        for pf in ["MD", "JSON", "SH"]:
            if pf in fmts:
                self._load_content(sid, pf, paths[pf])
                return

        self._vtitle.value = f"\U0001f4c4 {sid}"
        self._vcont.value = self.t("bin")
        self.page.update()

    def _load_content(self, sid: str, fmt: str, fp: str):
        """Load report content for preview."""
        self._vtitle.value = f"\U0001f4c4 {sid} [{fmt}]"
        if not Path(fp).exists():
            self._vcont.value = f"Not found: {fp}"
            self.page.update()
            return

        if fmt in ("PDF", "DOCX"):
            self._vcont.value = f"{self.t('bin')}\n\U0001f4c1 {fp}"
            self.page.update()
            return

        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                self._vcont.value = f.read()
        except Exception as ex:
            self._vcont.value = f"Error: {ex}"
        self.page.update()

    def _on_refresh(self, e):
        self._load_reports()
        self._vtitle.value = self.t("selrep")
        self._vcont.value = ""
        self._ftabs.controls.clear()
        self._snack(self.t("ref"), C.T)
        self.page.update()

    def _on_open_folder(self, e):
        import platform
        import subprocess
        rr = str(self.state.root / "reports")
        try:
            if platform.system() == "Darwin":
                subprocess.Popen(["open", rr])
            elif platform.system() == "Linux":
                subprocess.Popen(["xdg-open", rr])
            else:
                subprocess.Popen(["explorer", rr])
        except Exception:
            self._snack(f"Open: {rr}", C.O)

    def _on_recreate(self, e):
        """Recreate last failed report from cached state."""
        state_file = self.state.data_dir / ".vura_state.json"
        if not state_file.exists():
            self._snack(self.t("recreate_no"), C.O)
            return

        self._snack(self.t("recreating"), C.Y)

        def do():
            try:
                with open(state_file, "r", encoding="utf-8") as f:
                    state = json.load(f)

                raw = state.get("raw_data") or ""
                if not raw.strip():
                    return "ERROR: No raw_data in state file"

                from app.core.ai_engine import generate_report
                from app.utils.formatter import (
                    save_markdown_report, export_to_pdf, export_to_docx,
                    save_json_report, add_compliance_section,
                )

                tool = state.get("tool") or "Unknown"
                ctx = state.get("context") or "Recreated report"
                of = state.get("format", "md")
                la = state.get("language", "English")
                ap = state.get("approach", "defense")

                import datetime, re
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_tool = re.sub(r'[^A-Za-z0-9_-]', '', tool) or "Scan"
                sid = f"VURA_{safe_tool}_{ts}"
                prep = f"Tool Used: {tool}\nContext: {ctx}\n\nTerminal Output:\n{raw}"

                ct = generate_report(
                    prep, language=la, output_format=of, approach=ap,
                    include_script=False, scan_type="terminal", report_context=ctx,
                )
                if not ct:
                    return "ERROR: AI returned empty"
                if of != "json":
                    ct = add_compliance_section(ct)

                if of == "json":
                    save_json_report(ct, sid)
                elif of == "pdf":
                    _, _, en = save_markdown_report(ct, sid, ap)
                    export_to_pdf(en, sid)
                elif of == "docx":
                    _, _, en = save_markdown_report(ct, sid, ap)
                    export_to_docx(en, sid)
                else:
                    save_markdown_report(ct, sid, ap)

                return "OK"

            except Exception as ex:
                return f"ERROR: {ex}"

        def done(r):
            if r == "OK":
                self._snack(self.t("recreate_ok"), C.G)
                self._load_reports()
                self.page.update()
            else:
                self._snack(str(r), C.R)

        self._run_bg(do, done)

    def _snack(self, msg: str, color=None):
        if hasattr(self, '_show_snack'):
            self._show_snack(msg, color)
