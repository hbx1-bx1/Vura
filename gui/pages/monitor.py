"""
VURA GUI — Monitor Page
═══════════════════════════════════
Ghost Monitor controls: start, hookall, exclude, stop, discard.
"""

from __future__ import annotations

from typing import Optional

import flet as ft

from gui.pages.base import BasePage, AppState
from gui.theme import C
from gui.components.buttons import btn
from gui.components.cards import card, section_header


class MonitorPage(BasePage):
    """Ghost Monitor control page."""

    def __init__(self, state: AppState, page: ft.Page):
        super().__init__(state, page)
        self._out: Optional[ft.Text] = None
        self._ss: Optional[ft.Text] = None
        self._si: Optional[ft.Icon] = None
        self._silent_cb: Optional[ft.Checkbox] = None

    def build(self) -> ft.Control:
        self._out = ft.Text("", size=12, color=C.DM, selectable=True)
        self._ss = ft.Text("...", size=14, color=C.DM)
        self._si = ft.Icon(ft.Icons.FIBER_MANUAL_RECORD, color=C.DM, size=16)
        self._silent_cb = ft.Checkbox(label=self.t("silent_mode"), value=False)

        self._refresh_status()

        return ft.Column([
            section_header(self.t("ghost"), ft.Icons.RADIO_BUTTON_CHECKED),
            ft.Container(height=8),
            card([ft.Row([self._si, self._ss], spacing=8)], title=self.t("sesst")),
            ft.Container(height=10),
            ft.Row([
                btn(self.t("start_ghost"), ft.Icons.PLAY_ARROW, self._on_start, C.T, 200),
                btn(self.t("start_hookall"), ft.Icons.ALL_INCLUSIVE, self._on_hookall, C.CD, 200),
                btn(self.t("exclude"), ft.Icons.BLOCK, self._on_exclude, C.S2, 200),
            ], spacing=10, wrap=True),
            ft.Row([
                btn(self.t("stop_collect"), ft.Icons.STOP_CIRCLE,
                    self._on_stop_collect, C.O, 200),
                btn(self.t("stop_report"), ft.Icons.SUMMARIZE,
                    self._on_stop_report, C.T2, 220),
                btn(self.t("discard"), ft.Icons.DELETE,
                    self._on_discard, C.R, 140),
            ], spacing=10, wrap=True),
            self._silent_cb,
            ft.Container(height=10),
            card([self._out], title=self.t("out")),
            ft.Container(height=10),
            card([ft.Text(self.t("how_txt"), size=12, color=C.DM)], title=self.t("how")),
        ], scroll=ft.ScrollMode.AUTO, spacing=8)

    def _refresh_status(self):
        """Update session status display."""
        engine = self.state.ghost_engine
        if engine.is_active():
            self._ss.value = f"{self.t('rec')} ({engine.get_size()})"
            self._ss.color = C.G
            self._si.color = C.G
        else:
            self._ss.value = self.t("nosess")
            self._ss.color = C.DM
            self._si.color = C.DM
        self.page.update()

    def _on_start(self, e):
        """Start Ghost Monitor."""
        from gui.engine import ghost_start
        ok, msg = ghost_start()
        self._out.value = msg
        self._out.color = C.G if ok else C.R
        if ok:
            self._snack(self.t("rec"), C.G)
        self._refresh_status()
        self.page.update()

    def _on_hookall(self, e):
        """Start HookAll reading."""
        from gui.engine import ghost_hookall
        self._out.value = self.t("hookall_reading")
        self._out.color = C.Y
        self.page.update()

        def do():
            return ghost_hookall()

        def done(r):
            ok, msg, cnt = r
            if ok and cnt > 0:
                self.state.ghost_data["raw"] = msg
                self._out.value = (
                    self.t("hookall_done").format(n=len(msg), t=cnt)
                    + f"\n\n{msg}"
                )
                self._out.color = C.G
                self._snack(self.t("hookall_done").format(n=len(msg), t=cnt), C.G)
            else:
                self._out.value = self.t("hookall_none")
                self._out.color = C.O
            self._refresh_status()

        self._run_bg(do, done)

    def _on_exclude(self, e):
        """Show terminal exclusion dialog."""
        from gui.engine import ghost_list_terminals, ghost_get_excluded, ghost_exclude_terminals
        terms = ghost_list_terminals()
        excluded = ghost_get_excluded()

        if not terms:
            self._out.value = "No interactive terminals found."
            self._out.color = C.O
            self.page.update()
            return

        cb_map = {}
        cb_col = ft.Column(spacing=4, scroll=ft.ScrollMode.AUTO, height=300)

        for ti in terms:
            tpath = ti["path"]
            tname = ti["name"]
            shell = ti["shell"]
            pid = ti["pid"]
            already = tpath in excluded

            cb = ft.Checkbox(label="", value=already, disabled=already)
            shell_color = C.G if not already else C.DM
            name_color = C.W if not already else C.DM

            row_items = [
                cb,
                ft.Icon(ft.Icons.TERMINAL, color=shell_color, size=16),
                ft.Text(f"{tname}", size=13, weight=ft.FontWeight.BOLD,
                        color=name_color, font_family="monospace"),
                ft.Container(
                    content=ft.Text(shell, size=10, color=C.W, weight=ft.FontWeight.W_600),
                    bgcolor=C.T if not already else C.N3,
                    border_radius=4,
                    padding=ft.Padding.symmetric(horizontal=8, vertical=2),
                ),
            ]
            if already:
                row_items.append(ft.Text("excluded", size=10, color=C.O, italic=True))
            elif pid:
                row_items.append(ft.Text(f"PID {pid}", size=10, color=C.DM))

            row = ft.Row(row_items, spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER)
            cb_map[tpath] = cb
            cb_col.controls.append(
                ft.Container(
                    content=row,
                    bgcolor=C.N3 if not already else C.N,
                    border_radius=8,
                    padding=ft.Padding.symmetric(horizontal=10, vertical=6),
                )
            )

        result_txt = ft.Text("", size=12)

        def do_exclude(ev):
            selected = [p for p, c in cb_map.items() if c.value and p not in excluded]
            if not selected:
                result_txt.value = "No new terminals selected."
                result_txt.color = C.O
                self.page.update()
                return
            ok, msg = ghost_exclude_terminals(selected)
            if ok:
                result_txt.value = f"\u2714 {msg}"
                result_txt.color = C.G
                self._out.value = f"\u2714 {msg}"
                self._out.color = C.G
                self._snack(self.t("excluded"), C.G)
                for p in selected:
                    cb_map[p].disabled = True
            else:
                result_txt.value = f"\u2718 {msg}"
                result_txt.color = C.R
            self.page.update()

        def close_dlg(ev):
            dlg.open = False
            self.page.update()

        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Row([
                ft.Icon(ft.Icons.DEVICES, color=C.T, size=22),
                ft.Text("Active Terminals", size=18, weight=ft.FontWeight.BOLD, color=C.T),
            ], spacing=8),
            content=ft.Container(
                content=ft.Column([
                    ft.Text("Select interactive terminals to exclude from HookAll:",
                            size=13, color=C.DM),
                    ft.Text(f"{len(terms)} interactive terminal(s) detected",
                            size=11, color=C.DM, italic=True),
                    ft.Container(height=6),
                    cb_col,
                    ft.Container(height=8),
                    result_txt,
                ], tight=True),
                width=480, height=420,
            ),
            actions=[
                ft.TextButton("Cancel", on_click=close_dlg),
                ft.Button("Exclude Selected", icon=ft.Icons.BLOCK,
                          bgcolor=C.T, color=C.W, on_click=do_exclude),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
            bgcolor=C.N2,
            shape=ft.RoundedRectangleBorder(radius=12),
        )
        self.page.overlay.append(dlg)
        dlg.open = True
        self.page.update()

    def _on_stop_collect(self, e):
        """Stop recording and save data for Analyze page."""
        from gui.engine import ghost_stop
        self._out.value = self.t("stop_msg")
        self._out.color = C.Y
        self.page.update()

        def do():
            return ghost_stop()

        def done(r):
            if r:
                n = len(r)
                self._out.value = self.t("capt").format(n=f"{n:,}")
                self._out.color = C.G
                self.state.ghost_data["raw"] = r
                self._snack(f"{n:,} chars", C.G)
            else:
                self._out.value = self.t("nosf")
                self._out.color = C.O
            self._refresh_status()

        self._run_bg(do, done)

    def _on_stop_report(self, e):
        """Stop recording and generate AI report directly."""
        from gui.engine import ghost_stop
        self._out.value = self.t("stop_msg")
        self._out.color = C.Y
        self.page.update()

        def do():
            raw = ghost_stop()
            if not raw:
                raw = self.state.ghost_data.get("raw")
            if not raw:
                log_file = self.state.log_file
                if log_file.exists():
                    try:
                        from gui.engine.helpers import clean_ansi
                        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                            raw = clean_ansi(f.read())
                    except Exception:
                        pass
            if not raw or len(raw.strip()) < 5:
                return "WARN: No data collected yet."

            self.state.ghost_data["raw"] = raw

            try:
                from app.core.ai_engine import generate_report
                from app.utils.formatter import save_markdown_report, add_compliance_section
                import datetime
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                sid = f"VURA_Ghost_{ts}"
                prep = f"Tool: Ghost Monitor\nContext: Live terminal\n\nOutput:\n{raw}"
                rep_lang = self.state.lang.report_language()
                ct = generate_report(
                    prep, language=rep_lang, output_format="md",
                    approach="defense", include_script=False,
                    scan_type="terminal", report_context="",
                )
                if not ct:
                    return "ERROR: AI returned empty response"
                ct = add_compliance_section(ct)
                sv, _, _ = save_markdown_report(ct, sid, "defense")
                return f"OK: {self.t('rsaved')} {sv}\n\n{ct[:1500]}" if sv else f"OK:\n{ct[:1500]}"
            except Exception as ex:
                return f"ERROR: {ex}"

        def done(r):
            msg = str(r)
            if msg.startswith("WARN:"):
                self._out.value = msg[5:].strip()
                self._out.color = C.O
                self._snack(msg[5:].strip(), C.O)
            elif msg.startswith("ERROR:"):
                self._out.value = msg
                self._out.color = C.R
            else:
                self._out.value = msg[3:].strip() if msg.startswith("OK:") else msg
                self._out.color = C.G
                self._snack(self.t("rok"), C.G)
            self._refresh_status()

        self._run_bg(do, done)

    def _on_discard(self, e):
        """Discard current session."""
        from gui.engine import ghost_discard
        ghost_discard()
        self.state.ghost_data["raw"] = None
        self._out.value = self.t("disc")
        self._out.color = C.Y
        self._snack(self.t("disc"), C.O)
        self._refresh_status()
        self.page.update()

    def _snack(self, msg: str, color=None):
        """Show snack bar — called via main.py snack reference."""
        if hasattr(self, '_show_snack'):
            self._show_snack(msg, color)
