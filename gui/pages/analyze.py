"""
VURA GUI — Analyze Page
═══════════════════════════════════
Report generation: manual input, file, ghost data, or terminal history.
"""

from __future__ import annotations

import datetime
import traceback
from pathlib import Path
from typing import Optional

import flet as ft

from gui.pages.base import BasePage, AppState
from gui.theme import C
from gui.components.buttons import btn
from gui.components.cards import card, section_header


RTYPES = {
    "1": {"n": "Network Scan", "a": "فحص الشبكة", "i": "\U0001f310",
          "c": "Network \u2014 ports, services, firewalls."},
    "2": {"n": "Web Application", "a": "تطبيق ويب", "i": "\U0001f578\ufe0f",
          "c": "Web \u2014 XSS, SQLi, CSRF, headers."},
    "3": {"n": "Recon / OSINT", "a": "استطلاع", "i": "\U0001f50d",
          "c": "Recon \u2014 subdomains, emails, services."},
    "4": {"n": "Vuln Assessment", "a": "تقييم ثغرات", "i": "\U0001f6e1\ufe0f",
          "c": "Vulnerability assessment \u2014 CVSS."},
    "5": {"n": "Custom", "a": "مخصّص", "i": "\U0001f4dd", "c": ""},
}

LANGS = [
    "English", "Arabic", "French", "Spanish", "German", "Japanese", "Chinese",
    "Korean", "Russian", "Portuguese", "Italian", "Turkish", "Dutch", "Hindi",
]


class AnalyzePage(BasePage):
    """Report generation page with tabbed input modes."""

    def __init__(self, state: AppState, page: ft.Page):
        super().__init__(state, page)
        self._tab_idx = [0]
        self._out: Optional[ft.Text] = None
        self._pr: Optional[ft.ProgressRing] = None
        self._mi: Optional[ft.TextField] = None
        self._fi: Optional[ft.TextField] = None
        self._hl: Optional[ft.TextField] = None
        self._rtd: Optional[ft.Dropdown] = None
        self._cdd: Optional[ft.TextField] = None
        self._fmd: Optional[ft.Dropdown] = None
        self._lnd: Optional[ft.Dropdown] = None
        self._apd: Optional[ft.Dropdown] = None
        self._std: Optional[ft.Dropdown] = None
        self._ntd: Optional[ft.Dropdown] = None
        self._tabs_row: Optional[ft.Row] = None

    def build(self) -> ft.Control:
        self._out = ft.Text("", size=12, color=C.DM, selectable=True)
        self._pr = ft.ProgressRing(width=24, height=24, color=C.T, visible=False)
        self._tabs_row = ft.Row(spacing=0)

        tab_labels = [self.t("man"), self.t("file"), self.t("gdata"), self.t("hist")]
        self._mi = self._tf(self.t("paste"), multiline=True, lines=6)
        self._fi = self._tf(self.t("fpath"), icon=ft.Icons.ATTACH_FILE, width=500)
        self._hl = self._tf(self.t("hlines"), value="50", width=100)

        nk = self.state.lang.label_key()
        self._rtd = self._dd(self.t("rtype"), [
            (k, f"{v['i']} {v.get(nk, v['n'])}") for k, v in RTYPES.items()
        ], "1", 280)

        self._cdd = self._tf(self.t("cdesc"))
        self._cdd.visible = False

        def on_rtype_change(e):
            self._cdd.visible = (self._rtd.value == "5")
            self.page.update()

        self._rtd.on_change = on_rtype_change

        self._fmd = self._dd(self.t("fmt"), [
            ("md", "Markdown"), ("pdf", "PDF"), ("docx", "DOCX"), ("json", "JSON")
        ], "md", 140)

        default_lang = "Arabic" if self.state.lang.is_arabic() else "English"
        self._lnd = self._dd(self.t("lang"), LANGS, default_lang, 180)

        self._apd = self._dd(self.t("appr"), [
            ("defense", self.t("defense")), ("offense", self.t("offense"))
        ], "defense", 160)

        self._std = self._dd(self.t("stype"), [
            ("terminal", "Terminal"), ("recon", "Recon"),
            ("executive", "Executive"), ("dual", "Dual")
        ], "terminal", 160)

        self._ntd = self._dd(self.t("notify"), [
            ("", "None"), ("short", "Short"), ("long", "Long")
        ], "", 140)

        self._build_tabs(tab_labels)

        return ft.Column([
            section_header(self.t("anly"), ft.Icons.ANALYTICS),
            ft.Container(height=6),
            self._tabs_row,
            ft.Container(height=6),
            self._mi,
            self._fi,
            ft.Row([ft.Text(self.t("hlines") + ":", color=C.DM, size=13), self._hl], spacing=8),
            ft.Divider(color=C.N3),
            ft.Row([self._rtd, self._fmd, self._lnd], spacing=10, wrap=True),
            self._cdd,
            ft.Row([self._apd, self._std, self._ntd], spacing=10, wrap=True),
            ft.Container(height=8),
            ft.Row([btn(self.t("gen"), ft.Icons.AUTO_AWESOME,
                        self._on_gen, C.T, 220), self._pr], spacing=12),
            ft.Container(height=10),
            card([self._out], title=self.t("out")),
        ], scroll=ft.ScrollMode.AUTO, spacing=8)

    def _build_tabs(self, labels):
        """Build tab selector row."""
        self._tabs_row.controls.clear()
        for i, lb in enumerate(labels):
            active = i == self._tab_idx[0]
            self._tabs_row.controls.append(
                ft.Container(
                    content=ft.Text(lb, size=13,
                                    color=C.T if active else C.DM,
                                    weight=ft.FontWeight.BOLD if active else ft.FontWeight.NORMAL),
                    border=ft.Border.only(
                        bottom=ft.BorderSide(2, C.T) if active else ft.BorderSide(1, C.N3)
                    ),
                    padding=ft.Padding.symmetric(horizontal=16, vertical=10),
                    on_click=lambda e, idx=i: self._set_tab(idx),
                )
            )

    def _set_tab(self, idx):
        self._tab_idx[0] = idx
        self._build_tabs(list_labels())
        self.page.update()

    def _on_gen(self, e):
        """Generate report from selected input source."""
        idx = self._tab_idx[0]
        raw = None

        if idx == 0:
            raw = self._mi.value
        elif idx == 1:
            fp = self._fi.value.strip() if self._fi.value else ""
            if fp and Path(fp).exists():
                try:
                    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                        raw = f.read()
                except Exception as ex:
                    self._out.value = f"Error: {ex}"
                    self._out.color = C.R
                    self.page.update()
                    return
            else:
                self._snack(self.t("fpath"), C.R)
                return
        elif idx == 2:
            raw = self.state.ghost_data.get("raw")
            if not raw:
                self._snack(self.t("nogd"), C.O)
                return
        elif idx == 3:
            try:
                from app.cli import read_terminal_history
                raw = read_terminal_history(int(self._hl.value or "50"))
            except Exception as ex:
                self._out.value = f"Error: {ex}"
                self._out.color = C.R
                self.page.update()
                return

        if not raw or len(raw.strip()) < 5:
            self._snack(self.t("nodata"), C.O)
            return

        rk = self._rtd.value or "1"
        rt = RTYPES[rk]
        rc = rt["c"]
        if rk == "5":
            rc = self._cdd.value.strip() or "General"

        of = self._fmd.value or "md"
        la = self._lnd.value or "English"
        ap = self._apd.value or "defense"
        sty = self._std.value or "terminal"
        nt = self._ntd.value or None

        self._pr.visible = True
        self._out.value = self.t("gening")
        self._out.color = C.Y
        self.page.update()

        def _generate():
            try:
                from app.core.ai_engine import generate_report
                from app.utils.formatter import (
                    save_markdown_report, export_to_pdf, export_to_docx,
                    save_json_report, add_compliance_section, generate_dual_reports,
                )

                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                sid = f"VURA_GUI_{ts}"
                prep = f"Tool: GUI\nContext: {rt['n']}\n\nOutput:\n{raw}"

                if sty == "dual":
                    res = generate_dual_reports(
                        raw_data=prep, session_id=sid, approach=ap,
                        language=la, output_format=of, include_script=False, notify=nt,
                    )
                    if res and res.get("technical", {}).get("content"):
                        return (
                            f"\u2714 Dual!\nTech: {res['technical'].get('md', '')}\n"
                            f"Exec: {res['executive'].get('md', '')}"
                        )
                    return "ERROR: Dual failed"

                ct = generate_report(
                    prep, language=la, output_format=of, approach=ap,
                    include_script=False, scan_type=sty, report_context=rc,
                )
                if not ct:
                    return "ERROR: AI empty"
                if any(ct.startswith(m) for m in ["# Connection Error", "# VURA Error", "# Error\n"]):
                    return f"ERROR:\n{ct[:500]}"
                if of != "json" and sty != "executive":
                    ct = add_compliance_section(ct)

                sv = None
                if of == "json":
                    sv = save_json_report(ct, sid)
                elif of == "pdf":
                    _, _, en = save_markdown_report(ct, sid, ap)
                    sv = export_to_pdf(en, sid)
                elif of == "docx":
                    _, _, en = save_markdown_report(ct, sid, ap)
                    sv = export_to_docx(en, sid)
                else:
                    sv, _, _ = save_markdown_report(ct, sid, ap)

                if nt:
                    try:
                        from app.utils.notifier import send_telegram_alert, send_telegram_file
                        send_telegram_alert(sv, ct, mode=nt)
                        if of == "pdf" and sv:
                            send_telegram_file(sv, f"VURA Report \u2014 {sid}")
                    except Exception:
                        pass

                return f"\u2714 {self.t('rsaved')} {sv}\n\n{ct[:2000]}" if sv else f"\u2714\n{ct[:2000]}"

            except Exception as ex:
                return f"ERROR: {ex}\n{traceback.format_exc()}"

        def _done(r):
            self._pr.visible = False
            if str(r).startswith("ERROR"):
                self._out.value = str(r)
                self._out.color = C.R
                self._snack(self.t("rfail"), C.R)
            else:
                self._out.value = str(r)
                self._out.color = C.G
                self._snack(self.t("rok"), C.G)

        self._run_bg(_generate, _done)

    def _snack(self, msg: str, color=None):
        if hasattr(self, '_show_snack'):
            self._show_snack(msg, color)


def list_labels():
    """Helper for tab label refresh (uses global i18n)."""
    return []
