"""
VURA GUI — Recon Page
═══════════════════════════════════
OSINT reconnaissance scan with parallel tool execution and per-tool progress.
"""

from __future__ import annotations

import datetime
import threading
import traceback
from typing import Optional

import flet as ft

from gui.pages.base import BasePage, AppState
from gui.theme import C
from gui.components.buttons import btn
from gui.components.cards import card, section_header


LANGS = [
    "English", "Arabic", "French", "Spanish", "German", "Japanese", "Chinese",
    "Korean", "Russian", "Portuguese", "Italian", "Turkish", "Dutch", "Hindi",
]

TOOL_LABELS = {
    "whois":        "WHOIS",
    "amass":        "Amass",
    "theharvester": "theHarvester",
    "shodan":       "Shodan",
    "nmap":         "Nmap",
}


class ReconPage(BasePage):
    """Recon / OSINT scan page with parallel execution."""

    def __init__(self, state: AppState, page: ft.Page):
        super().__init__(state, page)
        self._out: Optional[ft.Text] = None
        self._rp: Optional[ft.ProgressRing] = None
        self._di: Optional[ft.TextField] = None
        self._rl: Optional[ft.Dropdown] = None
        self._rf: Optional[ft.Dropdown] = None
        self._tst: Optional[ft.Text] = None
        self._progress_bars: dict[str, ft.ProgressBar] = {}
        self._progress_labels: dict[str, ft.Text] = {}
        self._progress_container: Optional[ft.Column] = None

    def build(self) -> ft.Control:
        self._out = ft.Text("", size=12, color=C.DM, selectable=True)
        self._rp = ft.ProgressRing(width=24, height=24, color=C.T, visible=False)
        self._di = self._tf(self.t("tdom"), icon=ft.Icons.LANGUAGE, width=400)
        default_lang = "Arabic" if self.state.lang.is_arabic() else "English"
        self._rl = self._dd(self.t("lang"), LANGS, default_lang, 160)
        self._rf = self._dd(self.t("fmt"), [
            ("md", "Markdown"), ("pdf", "PDF"), ("docx", "DOCX"), ("json", "JSON")
        ], "md", 140)

        sa = ft.Checkbox(label="Amass")
        sh = ft.Checkbox(label="theHarvester")
        ss = ft.Checkbox(label="Shodan")
        sn = ft.Checkbox(label="Nmap")
        sw = ft.Checkbox(label="Whois")

        self._tst = ft.Text("...", size=12, color=C.DM)

        # Per-tool progress bars (hidden until scan starts)
        self._progress_container = ft.Column([], spacing=6, visible=False)
        for tool in ["whois", "amass", "theharvester", "shodan", "nmap"]:
            bar = ft.ProgressBar(width=400, color=C.T, bgcolor=C.D4)
            label = ft.Text("", size=11, color=C.DM)
            self._progress_bars[tool] = bar
            self._progress_labels[tool] = label
            self._progress_container.controls.append(
                ft.Row([
                    ft.Text(TOOL_LABELS[tool], size=12, color=C.DL, width=120),
                    ft.Container(bar, expand=True),
                    label,
                ], spacing=10)
            )

        # Check tools in background
        def check_tools():
            try:
                from app.core.recon import check_all_tools
                tools = check_all_tools()
                self._tst.value = "  |  ".join([
                    f"\u2714 {k}" if v else f"\u2718 {k}" for k, v in tools.items()
                ])
            except Exception:
                self._tst.value = self.t("uchk")
            self.page.update()

        threading.Thread(target=check_tools, daemon=True).start()

        def on_run(e):
            d = self._di.value.strip()
            if not d:
                self._snack(self.t("edom"), C.O)
                return

            self._rp.visible = True
            self._out.value = ""
            self._out.color = C.DM

            # Show and reset progress bars
            self._progress_container.visible = True
            for tool in self._progress_bars:
                self._progress_bars[tool].value = None  # indeterminate
                self._progress_labels[tool].value = "\u23f3 Pending"
            self.page.update()

            def do():
                try:
                    from app.core.recon import (
                        run_full_recon_parallel, aggregate_results,
                        ReconProgress,
                    )
                    from app.core.ai_engine import generate_report
                    from app.utils.formatter import (
                        save_markdown_report, export_to_pdf, export_to_docx,
                        save_json_report, add_compliance_section,
                    )

                    # Progress callback — updates GUI from background thread
                    def on_progress(progress: ReconProgress):
                        def update_ui():
                            bar = self._progress_bars.get(progress.tool)
                            lbl = self._progress_labels.get(progress.tool)
                            if not bar or not lbl:
                                return

                            if progress.status == "starting":
                                bar.value = None  # indeterminate spinner
                                lbl.value = "\u23f3 Starting..."
                            elif progress.status == "done":
                                bar.value = 1.0
                                lbl.value = f"\u2714 {progress.message}"
                                lbl.color = C.G
                            elif progress.status == "failed":
                                bar.value = 1.0
                                lbl.value = f"\u2718 {progress.message}"
                                lbl.color = C.R
                            elif progress.status == "skipped":
                                bar.value = 0
                                lbl.value = "\u2298 Skipped"
                                lbl.color = C.DM
                            self.page.update()

                        self.page.run_thread(update_ui)

                    results, summary = run_full_recon_parallel(
                        d,
                        skip_amass=sa.value,
                        skip_theharvester=sh.value,
                        skip_shodan=ss.value,
                        skip_nmap=sn.value,
                        skip_whois=sw.value,
                        progress_callback=on_progress,
                    )

                    if not results:
                        return "ERROR: No tools executed"

                    agg = aggregate_results(*results)
                    if not agg or len(agg.strip()) < 20:
                        return "ERROR: No data"

                    la = self._rl.value or "English"
                    fm = self._rf.value or "md"
                    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    sid = f"VURA_Recon_{ts}"

                    ct = generate_report(
                        f"Tool: Recon\nContext: {d}\n\n{agg}",
                        language=la, output_format=fm, approach="defense",
                        include_script=False, scan_type="recon",
                        report_context="Recon/OSINT",
                    )
                    if not ct:
                        return "ERROR: AI empty"
                    if fm != "json":
                        ct = add_compliance_section(ct)

                    sv = None
                    if fm == "json":
                        sv = save_json_report(ct, sid)
                    elif fm == "pdf":
                        _, _, en = save_markdown_report(ct, sid, "defense")
                        sv = export_to_pdf(en, sid)
                    elif fm == "docx":
                        _, _, en = save_markdown_report(ct, sid, "defense")
                        sv = export_to_docx(en, sid)
                    else:
                        sv, _, _ = save_markdown_report(ct, sid, "defense")

                    lines = [
                        f"\u2714 {summary['success']}/{summary['total']} tools succeeded",
                        f"\u23f1 Total time: {summary['duration']}s",
                        f"\u2705 Report saved: {sv}" if sv else "",
                        "",
                        agg[:600],
                    ]
                    if ct:
                        lines.append(f"\n{'─' * 40}\n{ct[:600]}")
                    return "\n".join(lines)

                except Exception as ex:
                    return f"ERROR: {ex}\n{traceback.format_exc()}"

            def done(r):
                self._rp.visible = False
                if str(r).startswith("ERROR"):
                    self._out.value = str(r)
                    self._out.color = C.R
                else:
                    self._out.value = str(r)
                    self._out.color = C.G
                    self._snack(self.t("rdone"), C.G)
                self.page.update()

            self._run_bg(do, done)

        return ft.Column([
            section_header(self.t("rtitle"), ft.Icons.RADAR),
            ft.Container(height=8),
            card([self._tst], title=self.t("tstat")),
            ft.Container(height=8),
            self._di,
            ft.Row([self._rl, self._rf], spacing=10),
            ft.Container(height=4),
            card([
                ft.Text(self.t("skip"), size=13, color=C.DM),
                ft.Row([sw, sa, sh, ss, sn], spacing=8, wrap=True),
            ]),
            ft.Container(height=8),
            self._progress_container,
            ft.Container(height=8),
            ft.Row([btn(self.t("rrun"), ft.Icons.PLAY_ARROW, on_run, C.T, 220), self._rp],
                   spacing=12),
            ft.Container(height=10),
            card([self._out], title=self.t("rout")),
        ], scroll=ft.ScrollMode.AUTO, spacing=8)

    def _snack(self, msg: str, color=None):
        if hasattr(self, '_show_snack'):
            self._show_snack(msg, color)
