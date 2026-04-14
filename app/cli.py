"""
VURA CLI — Command Handler & Report Processing Engine
═══════════════════════════════════════════════════════
Manages all CLI commands, report generation workflow,
scan tracking, and integration with all VURA modules.
"""

import sys
import argparse
from pathlib import Path
import json
from rich.prompt import Confirm, Prompt
from rich.console import Console
from rich.progress import Progress
from rich.table import Table
from rich.markdown import Markdown
from rich.syntax import Syntax
from app.core.monitor import (
    start_ghost_monitor, end_ghost_monitor,
    start_hookall, stop_hookall, is_hookall_active,
    exclude_terminal,
)
from app.core.ai_engine import generate_report
from app.utils.formatter import (
    save_markdown_report, export_to_pdf, export_to_docx, save_json_report,
    add_compliance_section, generate_dual_reports,
)
from app.utils.config import load_api_config, get_config_summary, validate_config, SUPPORTED_PROVIDERS
from app.utils.notifier import send_telegram_alert, send_telegram_file
from app.utils.logger import log

console = Console()

# ✅ FIX #4 — مسارات مطلقة بدلاً من النسبية
_PROJECT_ROOT = Path(__file__).parent.parent.absolute()
STATE_FILE     = _PROJECT_ROOT / "data" / ".vura_state.json"


# ═══════════════════════════════════════════════════════════════════════════════
# STATE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

def save_state(raw_data, tool_name, context, output_format, language, notify, approach, status="Pending"):
    state = {
        "tool": tool_name, "context": context, "format": output_format,
        "language": language, "notify": notify, "approach": approach,
        "status": status, "raw_data": raw_data,
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    try:
        STATE_FILE.parent.mkdir(exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except (IOError, OSError, TypeError) as e:
        console.print(f"[dim red][!] Failed to save state: {e}[/dim red]")


def get_last_status():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f).get("status", "Unknown")
    except (json.JSONDecodeError, IOError, KeyError, FileNotFoundError):
        return "Corrupted or Missing"


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

# ── Report Types ─────────────────────────────────────────────────────
REPORT_TYPES = {
    "1": {"name": "Network Scan",              "icon": "🌐", "has_script": True,
           "context": "Network infrastructure scan — analyze ports, services, firewalls, routing, and network-level vulnerabilities."},
    "2": {"name": "Web Application",           "icon": "🕸️",  "has_script": True,
           "context": "Web application security test — analyze XSS, SQL injection, CSRF, security headers, authentication flaws, and web-specific vulnerabilities."},
    "3": {"name": "Recon / OSINT",             "icon": "🔍", "has_script": True,
           "context": "Reconnaissance and OSINT operation — analyze discovered subdomains, emails, exposed services, attack surface, and intelligence gathered from public sources."},
    "4": {"name": "Vulnerability Assessment",  "icon": "🛡️",  "has_script": True,
           "context": "General vulnerability assessment — identify all security weaknesses, classify by severity (CVSS), and provide remediation guidance."},
    "5": {"name": "Custom",                    "icon": "📝", "has_script": False,
           "context": ""},
}

# ✅ FIX #1 (CRITICAL) — إعادة كتابة process_and_report بالكامل
# ✅ FIX #5 — دعم خيار -A من CLI بدون override
def process_and_report(raw_data, tool_name=None, context=None, output_format="md",
                       language="English", notify=None, approach="defense",
                       cli_approach=None, scan_type="terminal"):
    """
    المحرك الرئيسي للتقارير — التدفق:
    1. سؤال: ما نوع هذا التقرير؟ (يُرسل للـ AI كسياق)
    2. إذا Custom → اكتب وصف → يُرسل للـ AI
    3. توليد التقرير بالـ AI مع السياق المناسب
    4. حفظ وعرض التقرير
    5. إذا تقني → هل تريد ملف .sh؟ → دفاع أو هجوم؟
    """
    if not raw_data:
        console.print("[bold red][!] No data provided to analyze.[/bold red]")
        return

    log.info("Report generation started", tool=tool_name, scan_type=scan_type, language=language)

    # ── Dual Report — تدفق مختلف ──
    if scan_type == "dual":
        _handle_dual_report(raw_data, tool_name, context, output_format,
                            language, notify, approach, cli_approach)
        return

    # ══════════════════════════════════════════════════════════════════════
    # المرحلة 1: تصنيف التقرير — ما نوع هذا التقرير؟
    # ══════════════════════════════════════════════════════════════════════
    console.print(f"\n[bold cyan]{'─'*50}[/bold cyan]")
    console.print(f"[bold cyan]  What type of report is this?[/bold cyan]")
    console.print(f"[bold cyan]{'─'*50}[/bold cyan]")

    for key, rtype in REPORT_TYPES.items():
        console.print(f"  [bold green]{key}[/bold green]. {rtype['icon']}  {rtype['name']}")

    console.print()
    report_choice = Prompt.ask(
        "[>] Select report type",
        choices=list(REPORT_TYPES.keys()),
        default="1"
    )

    chosen_type = REPORT_TYPES[report_choice]
    report_label = chosen_type["name"]
    report_context = chosen_type["context"]

    # ── Custom → اكتب وصف — يُرسل للـ AI ──
    if report_choice == "5":
        custom_desc = input("[>] Describe what this report is about: ").strip()
        if custom_desc:
            report_label = custom_desc
            report_context = custom_desc
        else:
            report_context = "General security analysis"

    console.print(f"\n[bold green][✔] Report type: {chosen_type['icon']}  {report_label}[/bold green]")

    # ══════════════════════════════════════════════════════════════════════
    # المرحلة 2: توليد التقرير — الـ AI يعرف النوع ويحلل بناءً عليه
    # ══════════════════════════════════════════════════════════════════════
    save_state(raw_data, tool_name, context, output_format, language, notify, approach,
               "Generating... (API Processing)")

    timestamp  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_tool  = tool_name.replace(" ", "") if tool_name else "Scan"
    session_id = f"VURA_{safe_tool}_{timestamp}"
    prep_data  = f"Tool Used: {tool_name}\nContext: {context}\n\nTerminal Output:\n{raw_data}"

    console.print(f"\n[bold magenta][~] VURA AI Engine ({language} | {report_label})...[/bold magenta]")

    with Progress() as progress:
        task = progress.add_task(
            f"[cyan]Analyzing as {report_label} ({output_format.upper()})...", total=100
        )
        final_report_content = generate_report(
            prep_data, language=language, output_format=output_format,
            approach="defense", include_script=False, scan_type=scan_type,
            report_context=report_context
        )
        progress.update(task, advance=100)

    if not final_report_content:
        console.print("[bold red][!] API returned empty response![/bold red]")
        save_state(raw_data, tool_name, context, output_format, language, notify,
                   approach, "[red]Failed - Empty Response[/red]")
        log.error("API returned empty response", scan_type=scan_type)
        return

    # ── كشف أخطاء AI ──
    error_markers = ["# Connection Error", "# VURA Error", "# Error\n"]
    is_error = any(final_report_content.startswith(m) for m in error_markers)

    if output_format == "json":
        try:
            parsed = json.loads(
                final_report_content.replace("```json", "").replace("```", "").strip()
            )
            is_error = "error" in parsed
        except (json.JSONDecodeError, TypeError):
            pass

    if is_error:
        console.print("\n[bold red][!] API Error or High Load! Report generation failed.[/bold red]")
        console.print(f"[bold yellow]🔍 Debug Info:[/bold yellow] [white]{final_report_content.strip()[:300]}[/white]")
        console.print("[dim white]Run 'vura -Rc' to try again without losing your data.[/dim white]")
        save_state(raw_data, tool_name, context, output_format, language, notify,
                   approach, "[red]Failed - API Error[/red]")
        log.error("AI returned error", content=final_report_content[:200])
        return

    # ── Compliance Mapping ──
    if output_format != "json" and scan_type != "executive":
        final_report_content = add_compliance_section(final_report_content)

    # ══════════════════════════════════════════════════════════════════════
    # المرحلة 3: حفظ التقرير
    # ════════════════════════════════════════════════════════════════════════
    # ✅ FIX #1 (CRITICAL): حفظ التقرير فعلياً واستقبال القيم المرجعة
    saved_file_path        = None
    patcher_script         = None
    final_enriched_content = final_report_content

    if output_format == "json":
        saved_file_path = save_json_report(final_report_content, session_id)
        if saved_file_path:
            console.print(f"[bold green][✔] JSON Report saved: ./{saved_file_path}[/bold green]")

    elif output_format == "pdf":
        _md_path, _, final_enriched_content = save_markdown_report(
            final_report_content, session_id, "defense"
        )
        saved_file_path = export_to_pdf(final_enriched_content, session_id)
        if saved_file_path:
            console.print(f"[bold white][📂] PDF Report: ./{saved_file_path}[/bold white]\n")

    elif output_format == "docx":
        _md_path, _, final_enriched_content = save_markdown_report(
            final_report_content, session_id, "defense"
        )
        saved_file_path = export_to_docx(final_enriched_content, session_id)
        if saved_file_path:
            console.print(f"[bold white][📂] DOCX Report: ./{saved_file_path}[/bold white]\n")

    else:
        saved_file_path, _, final_enriched_content = save_markdown_report(
            final_report_content, session_id, "defense"
        )
        if saved_file_path:
            console.print(f"[bold green][✔] Markdown Report saved: ./{saved_file_path}[/bold green]")

    if not saved_file_path:
        save_state(raw_data, tool_name, context, output_format, language, notify,
                   approach, "[yellow]Warning - File not saved[/yellow]")
        log.warn("Report generated but file not saved", scan_type=scan_type)
        return

    # ══════════════════════════════════════════════════════════════════════
    # المرحلة 4: سكربت .sh — فقط للتقارير التقنية
    # ══════════════════════════════════════════════════════════════════════
    if chosen_type["has_script"]:
        want_script = Confirm.ask("\n[?] Generate an Action Bash Script (.sh)?")

        if want_script:
            if cli_approach:
                # ✅ FIX #5: نحترم الخيار القادم من CLI
                approach = cli_approach
                console.print(f"[dim][~] Using CLI approach: [bold]{approach}[/bold][/dim]")
            else:
                approach = Prompt.ask(
                    "[?] Script strategy",
                    choices=["defense", "offense"],
                    default="defense"
                )

            console.print(f"\n[bold magenta][~] Generating {approach.upper()} script...[/bold magenta]")

            with Progress() as progress:
                task = progress.add_task(
                    f"[cyan]Generating {approach.title()} Script...", total=100
                )
                script_report = generate_report(
                    prep_data, language=language, output_format="md",
                    approach=approach, include_script=True, scan_type=scan_type,
                    report_context=report_context
                )
                progress.update(task, advance=100)

            if script_report:
                from app.utils.formatter import generate_patch_script
                patcher_script = generate_patch_script(script_report, session_id, approach)

                if patcher_script:
                    script_type = "EXPLOIT" if approach == "offense" else "AUTO-PATCHER"
                    console.print(f"[bold cyan][🛡️] {script_type} Script: ./{patcher_script}[/bold cyan]")
                    console.print("[dim yellow][!] Review every command before executing.[/dim yellow]")
                else:
                    console.print("[yellow][~] AI did not generate bash blocks. No script file created.[/yellow]")
            else:
                console.print("[yellow][~] Script generation failed. Report is still saved.[/yellow]")

    # ── حفظ الحالة النهائية ──
    status_label = f"[green]Success ✔ ({report_label})[/green]"
    save_state(raw_data, tool_name, context, output_format, language, notify,
               approach, status_label)
    log.scan(scan_type, tool_name or "unknown", "completed",
             report=saved_file_path, classification=report_label,
             script=patcher_script)

    # ── Telegram ──
    if notify:
        _send_notification(notify, saved_file_path, final_enriched_content,
                           output_format, session_id)


def _send_notification(notify, saved_file_path, content, output_format, session_id):
    """إرسال إشعار Telegram."""
    console.print("[dim yellow][~] Sending Telegram Notification...[/dim yellow]")
    send_telegram_alert(saved_file_path, content, mode=notify)
    if output_format == "pdf" and saved_file_path:
        send_telegram_file(saved_file_path, f"VURA Report — {session_id}")


def _handle_dual_report(raw_data, tool_name, context, output_format,
                        language, notify, approach, cli_approach):
    """معالجة Dual Report — تقني + تنفيذي."""
    if cli_approach:
        approach = cli_approach

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_tool = tool_name.replace(" ", "") if tool_name else "Scan"
    session_id = f"VURA_{safe_tool}_{timestamp}"

    include_script = Confirm.ask("\n[?] Include Bash script in technical report?")

    results = generate_dual_reports(
        raw_data=f"Tool Used: {tool_name}\nContext: {context}\n\nTerminal Output:\n{raw_data}",
        session_id=session_id,
        approach=approach,
        language=language,
        output_format=output_format,
        include_script=include_script,
        notify=notify,
    )

    if results["technical"]["content"]:
        save_state(raw_data, tool_name, context, output_format, language, notify,
                   approach, "[green]Dual Report ✔[/green]")
        log.scan("dual", tool_name or "unknown", "completed")
    else:
        save_state(raw_data, tool_name, context, output_format, language, notify,
                   approach, "[red]Dual Report Failed[/red]")


# ═══════════════════════════════════════════════════════════════════════════════
# RECON COMMAND
# ═══════════════════════════════════════════════════════════════════════════════

def run_recon_scan(domain, language="English", output_format="md", notify=None,
                   approach="defense", skip_tools=None):
    """تشغيل Recon كامل على domain وتوليد تقرير."""
    from app.core.recon import run_full_recon

    skip_tools = skip_tools or {}
    console.print(f"\n[bold green][~] VURA Recon: Scanning {domain}...[/bold green]\n")
    log.scan("recon", domain, "started")

    aggregated = run_full_recon(
        domain,
        skip_amass=skip_tools.get("amass", False),
        skip_theharvester=skip_tools.get("theharvester", False),
        skip_shodan=skip_tools.get("shodan", False),
        skip_nmap=skip_tools.get("nmap", False),
        skip_whois=skip_tools.get("whois", False),
    )

    if not aggregated or len(aggregated.strip()) < 20:
        console.print("[bold red][!] Recon returned no usable data.[/bold red]")
        log.scan("recon", domain, "failed", reason="no data")
        return

    process_and_report(
        aggregated,
        tool_name="Recon",
        context=f"Full recon on {domain}",
        output_format=output_format,
        language=language,
        notify=notify,
        approach=approach,
        scan_type="recon",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM DIAGNOSTICS
# ═══════════════════════════════════════════════════════════════════════════════

def run_system_check():
    """فحص شامل لحالة كل مكونات VURA."""
    table = Table(title="VURA Smart Diagnostics", show_header=True, header_style="bold magenta")
    table.add_column("Component", style="bold cyan")
    table.add_column("Status")
    table.add_column("Details", style="dim")

    # ── License ──
    table.add_row("License", "[green]Free & Open Source ✔[/green]", "No license required")

    # ── AI Engine ──
    config_summary = get_config_summary()
    config_errors = validate_config()
    if not config_errors:
        ai_status = f"[green]Connected ({config_summary['provider']}) ✔[/green]"
        ai_detail = f"Model: {config_summary['model_name']}"
    else:
        ai_status = "[red]Not Configured ✘[/red]"
        ai_detail = config_errors[0]
    table.add_row("AI Engine", ai_status, ai_detail)

    # ── Telegram ──
    tg_status = "[green]Configured ✔[/green]" if config_summary["telegram"] == "Configured" else "[dim]Not set[/dim]"
    table.add_row("Telegram", tg_status, "")

    # ── Shodan ──
    shodan_status = "[green]Configured ✔[/green]" if config_summary["shodan"] == "Configured" else "[dim]Not set[/dim]"
    table.add_row("Shodan API", shodan_status, "")

    # ── Database ──
    try:
        from app.core.database import VuraDB
        db = VuraDB()
        stats = db.get_global_stats()
        db.close()
        db_status = f"[green]OK ✔[/green]"
        db_detail = f"{stats.get('total_clients', 0)} clients, {stats.get('total_scans', 0)} scans"
    except Exception:
        db_status = "[dim]Not initialized[/dim]"
        db_detail = "Will auto-create on first use"
    table.add_row("Database", db_status, db_detail)

    # ── Recon Tools ──
    try:
        from app.core.recon import check_all_tools
        tools = check_all_tools()
        installed = sum(1 for v in tools.values() if v)
        tools_status = f"[green]{installed}/{len(tools)} installed ✔[/green]" if installed else "[red]None ✘[/red]"
        missing = [k for k, v in tools.items() if not v]
        tools_detail = f"Missing: {', '.join(missing)}" if missing else "All available"
    except Exception:
        tools_status = "[dim]Cannot check[/dim]"
        tools_detail = ""
    table.add_row("Recon Tools", tools_status, tools_detail)

    # ── Last Task ──
    table.add_row("Last Task", get_last_status(), "")

    console.print(table)
    log.info("System check completed")


# ═══════════════════════════════════════════════════════════════════════════════
# HISTORY & ARCHIVE
# ═══════════════════════════════════════════════════════════════════════════════

def read_terminal_history(lines=50):
    history_file = os.path.expanduser("~/.bash_history")
    if "zsh" in os.environ.get("SHELL", ""):
        history_file = os.path.expanduser("~/.zsh_history")
    try:
        with open(history_file, "r", encoding="utf-8", errors="ignore") as f:
            return "".join(f.readlines()[-lines:])
    except (IOError, OSError):
        return None


def show_report_history():
    # ✅ FIX #4: مسار مطلق للتقارير
    reports_root = os.path.join(_PROJECT_ROOT, "reports")
    files = []
    for ext in ["md", "json", "pdf", "sh"]:
        files.extend(glob.glob(os.path.join(reports_root, ext, "*.*")))

    if not files:
        return console.print("[yellow][!] No reports found.[/yellow]")

    sessions = {}
    for path in files:
        name, ext = os.path.splitext(os.path.basename(path))
        ext = ext.replace(".", "").upper()
        if name not in sessions:
            sessions[name] = {"formats": [], "paths": {}}
        if ext not in sessions[name]["formats"]:
            sessions[name]["formats"].append(ext)
            sessions[name]["paths"][ext] = path

    table = Table(title="📂 VURA Structured Archive", show_header=True)
    table.add_column("No.", justify="center")
    table.add_column("Session ID")
    table.add_column("Formats", justify="center")

    i_map = {}
    for idx, (sess_id, data) in enumerate(sorted(sessions.items(), reverse=True), 1):
        f_str = ", ".join(
            [f"[green]{f}[/green]" if f == "MD" else f"[blue]{f}[/blue]" for f in data["formats"]]
        )
        table.add_row(str(idx), sess_id, f_str)
        i_map[str(idx)] = sess_id

    console.print(table)
    console.print(f"[dim]Total: {len(sessions)} session(s), {len(files)} file(s)[/dim]")

    choice = Prompt.ask("\n[>] Read report number (Enter to exit)", default="")
    if choice in i_map:
        sess_id   = i_map[choice]
        read_path = sessions[sess_id]["paths"].get(
            "MD", sessions[sess_id]["paths"].get("JSON", sessions[sess_id]["paths"].get("SH"))
        )
        if read_path:
            with open(read_path, "r", encoding="utf-8") as f:
                content = f.read()
            console.print(
                Markdown(content) if read_path.endswith(".md")
                else Syntax(content, "json", theme="monokai")
            )


# ═══════════════════════════════════════════════════════════════════════════════
# COMMAND HANDLER — نقطة الدخول الرئيسية
# ═══════════════════════════════════════════════════════════════════════════════

def handle_cli_commands(args):
    if args.check:
        run_system_check()
        return

    if args.history:
        show_report_history()
        return

    if args.recreate:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r") as f:
                state = json.load(f)
            console.print("[bold cyan][~] Re-creating previous failed report from cache...[/bold cyan]")
            process_and_report(
                state["raw_data"], state.get("tool"), state.get("context"),
                state.get("format", "md"), state.get("language", "English"),
                state.get("notify"), state.get("approach", "defense")
            )
        else:
            console.print("[bold red][!] No cache found to recreate.[/bold red]")
        return

    # ── Recon ──
    if hasattr(args, "recon") and args.recon:
        run_recon_scan(
            domain=args.recon,
            language=args.lang,
            output_format=args.format,
            notify=args.notify,
            approach=args.approach,
        )
        return

    # ── Dual Report ──
    scan_type = getattr(args, "scan_type", "terminal") or "terminal"

    if args.past:
        if args.past <= 0:
            console.print("[bold red][!] Lines must be positive.[/bold red]")
            return
        raw_data = read_terminal_history(args.past)
        if raw_data:
            process_and_report(
                raw_data, context=f"History: {args.past} cmds",
                output_format=args.format, language=args.lang,
                notify=args.notify, cli_approach=args.approach,  # ✅ FIX #5
                scan_type=scan_type,
            )
        return

    if args.hook:
        start_ghost_monitor(silent=args.silent)
        return

    if hasattr(args, "hookall") and args.hookall:
        start_hookall(silent=args.silent)
        return

    if hasattr(args, "exclude") and args.exclude:
        exclude_terminal()
        return

    if args.report:
        # ── فحص hookall أولاً — إذا نشط نوقفه ونجمع البيانات ──
        raw_data = None
        if is_hookall_active():
            raw_data = stop_hookall()
        if not raw_data:
            raw_data = end_ghost_monitor()
        if raw_data:
            process_and_report(
                raw_data, args.tool, "Live Terminal Hook",
                output_format=args.format, language=args.lang,
                notify=args.notify, cli_approach=args.approach,  # ✅ FIX #5
                scan_type=scan_type,
            )
        return

    if args.file:
        if os.path.exists(args.file):
            with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                raw_data = f.read()
            process_and_report(
                raw_data, args.tool, args.context,
                output_format=args.format, language=args.lang,
                notify=args.notify, cli_approach=args.approach,  # ✅ FIX #5
                scan_type=scan_type,
            )
        else:
            console.print(f"[bold red][!] File not found: '{args.file}'[/bold red]")
        return

    if args.manual:
        process_and_report(
            args.manual, args.tool, args.context,
            output_format=args.format, language=args.lang,
            notify=args.notify, cli_approach=args.approach,  # ✅ FIX #5
            scan_type=scan_type,
        )
        return

    console.print("[bold red][!] Invalid usage. Run 'vura -h' for help.[/bold red]")
