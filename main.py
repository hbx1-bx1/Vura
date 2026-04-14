"""
VURA — Vulnerability Reporting AI
═══════════════════════════════════════════════
AI-Powered Cybersecurity Analysis & Reporting Platform

Entry point: python main.py [commands]
"""

import sys
import os
import argparse
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.table import Table
from app.cli import handle_cli_commands
from app.utils.config import save_api_config, load_api_config, SUPPORTED_PROVIDERS

console = Console()

VURA_VERSION = "1.0.0"


def show_pro_banner():
    banner_text = r"""
    __      __ _    _  _____            
    \ \    / /| |  | ||  __ \    /\     
     \ \  / / | |  | || |__) |  /  \    
      \ \/ /  | |  | ||  _  /  / /\ \   
       \  /   | |__| || | \ \ / ____ \  
        \/     \____/ |_|  \_/_/    \_\
    """
    console.print(Align.center(Text(banner_text, style="bold green")))
    console.print(Align.center(Text("Vulnerability Reporting AI", style="italic cyan")))
    console.print(Align.center(Text(f"v{VURA_VERSION}", style="dim white")))
    console.print(Align.center(Text("—" * 50, style="dim white")))


def show_custom_help():
    show_pro_banner()
    console.print("[bold cyan]Welcome to VURA - Your AI-Powered Cybersecurity Co-Pilot![/bold cyan]\n")

    # ── Core Analysis ──
    table_core = Table(
        title="[bold yellow]🎯 Core Analysis Commands[/bold yellow]",
        show_lines=True, header_style="bold magenta", title_justify="left"
    )
    table_core.add_column("Short", style="bold green", justify="center")
    table_core.add_column("Long",  style="bold cyan")
    table_core.add_column("Description")
    table_core.add_row("-H",  "--hook",     "Start Ghost Monitor to record your live terminal.")
    table_core.add_row("-Ha", "--hookall", "[bold]Record ALL[/bold] open terminals simultaneously.")
    table_core.add_row("-e",  "--exclude", "Exclude this terminal from hookall recording.")
    table_core.add_row("-s",  "--silent",  "Run Ghost Monitor in silent mode (No prints).")
    table_core.add_row("-R",  "--report",  "Stop Ghost Monitor and generate a report.")
    table_core.add_row("-m",  "--manual", "Analyze a direct text input.")
    table_core.add_row("-f",  "--file",   "Analyze an existing log file.")
    table_core.add_row("-p",  "--past",   "Analyze the last N lines from your terminal history.")
    table_core.add_row("-r",  "--recon",  "[bold]Recon scan[/bold]: Full reconnaissance on a domain.")

    # ── Output & Strategy ──
    table_mods = Table(
        title="[bold yellow]🎨 Output & Strategy[/bold yellow]",
        show_lines=True, header_style="bold magenta", title_justify="left"
    )
    table_mods.add_column("Short", style="bold green", justify="center")
    table_mods.add_column("Long",  style="bold cyan")
    table_mods.add_column("Description")
    table_mods.add_row("-F", "--format",    "Output format: pdf, md, json (Default: md).")
    table_mods.add_row("-l", "--lang",      "Target language (any lang., English, Arabic).")
    table_mods.add_row("-A", "--approach",  "Strategy: [bold]defense[/bold] or [bold]offense[/bold].")
    table_mods.add_row("-S", "--scan-type", "[bold]Scan type[/bold]: terminal, recon, executive, dual.")
    table_mods.add_row("-n", "--notify",    "Telegram alert mode: short or long.")

    # ── System ──
    table_sys = Table(
        title="[bold yellow]⚙️ System & Recovery[/bold yellow]",
        show_lines=True, header_style="bold magenta", title_justify="left"
    )
    table_sys.add_column("Short", style="bold green", justify="center")
    table_sys.add_column("Long",  style="bold cyan")
    table_sys.add_column("Description")
    table_sys.add_row("-Ch", "--change-key", "Setup your AI Provider & API Keys.")
    table_sys.add_row("-Ck", "--check",      "Run system diagnostics.")
    table_sys.add_row("-Hy", "--history",     "Open the VURA Archive.")
    table_sys.add_row("-Rc",       "--recreate", "Re-create the last report if the AI API failed.")

    console.print(table_core)
    console.print(table_mods)
    console.print(table_sys)

    # ── Examples ──
    console.print("\n[bold yellow]📝 Examples:[/bold yellow]")
    console.print("  [dim]vura -H                          [/dim]Start recording current terminal")
    console.print("  [dim]vura -Ha                         [/dim]Record ALL open terminals")
    console.print("  [dim]vura -e                          [/dim]Exclude this terminal from hookall")
    console.print("  [dim]vura -R -F pdf -l Arabic          [/dim]Generate PDF report in Arabic")
    console.print("  [dim]vura -f scan.log -A offense        [/dim]Analyze log file with attack scripts")
    console.print("  [dim]vura -r example.com -F pdf         [/dim]Full recon on domain → PDF report")
    console.print("  [dim]vura -m 'nmap output...' -S dual   [/dim]Dual report (Technical + Executive)")
    console.print()


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h",  "--help",       action="store_true")
    parser.add_argument("-v",  "--version",    action="store_true")
    parser.add_argument("-Ch", "--change-key", action="store_true")

    parser.add_argument("-Ck", "--check",      action="store_true")

    parser.add_argument("-Hy", "--history",    action="store_true")
    parser.add_argument("-Rc", "--recreate",   action="store_true")
    parser.add_argument("-H",  "--hook",       action="store_true")
    parser.add_argument("-Ha", "--hookall",    action="store_true")
    parser.add_argument("-e",  "--exclude",    action="store_true")
    parser.add_argument("-s",  "--silent",     action="store_true")
    parser.add_argument("-R",  "--report",     action="store_true")
    parser.add_argument("-F",  "--format",     type=str, choices=["md", "json", "pdf", "docx"], default="md")
    parser.add_argument("-l",  "--lang",       type=str, default="English")
    parser.add_argument("-A",  "--approach",   type=str, choices=["defense", "offense"], default="defense")
    parser.add_argument("-S",  "--scan-type",  type=str, choices=["terminal", "recon", "executive", "dual"], default="terminal")
    parser.add_argument("-n",  "--notify",     type=str, choices=["short", "long"])
    parser.add_argument("-p",  "--past",       type=int, metavar="LINES")
    parser.add_argument("-f",  "--file",       type=str)
    parser.add_argument("-m",  "--manual",     type=str)
    parser.add_argument("-c",  "--context",    type=str)
    parser.add_argument("-t",  "--tool",       type=str)
    parser.add_argument("-r",  "--recon",      type=str, metavar="DOMAIN")

    args, _ = parser.parse_known_args()

    # ── لا أوامر ──
    if len(sys.argv) == 1:
        show_pro_banner()
        console.print("\n[bold yellow]For help, use:[/bold yellow] [bold white]vura -h[/bold white]\n")
        sys.exit(0)

    if args.help:
        show_custom_help()
        sys.exit(0)

    if args.version:
        console.print(f"VURA v{VURA_VERSION}")
        sys.exit(0)

    # ── Check — System diagnostics (no license required) ──
    if args.check:
        handle_cli_commands(args)
        sys.exit(0)

    # ═══════════════════════════════════════════════════════════════════════
    # Open Source — No License Restrictions
    # ═══════════════════════════════════════════════════════════════════════
    # VURA is now free and open source. No license verification needed.

    # ═══════════════════════════════════════════════════════════════════════
    # إعداد المفاتيح — -Ch
    # ═══════════════════════════════════════════════════════════════════════
    if args.change_key:
        console.print("\n[bold cyan][~] VURA Global Configuration[/bold cyan]")
        config_data = load_api_config() or {}

        providers_str = ", ".join(SUPPORTED_PROVIDERS)
        console.print(f"[dim]Supported providers: {providers_str}[/dim]\n")

        provider = input(f"Provider [{config_data.get('provider', '')}]: ").strip()
        if provider:
            config_data["provider"] = provider

        api_key = input("API Key: ").strip()
        if api_key:
            config_data["api_key"] = api_key

        model = input(f"Model Name [{config_data.get('model_name', '')}]: ").strip()
        if model:
            config_data["model_name"] = model

        if provider == "custom":
            base_url = input("Custom Base URL: ").strip()
            if base_url:
                config_data["base_url"] = base_url

        console.print("\n[dim]── Telegram (optional) ──[/dim]")
        tg_token = input("Telegram Bot Token: ").strip()
        if tg_token:
            config_data["tg_bot_token"] = tg_token
        tg_chat = input("Your Chat ID: ").strip()
        if tg_chat:
            config_data["tg_chat_id"] = tg_chat

        console.print("\n[dim]── Integrations (optional) ──[/dim]")
        shodan = input("Shodan API Key: ").strip()
        if shodan:
            config_data["shodan_api_key"] = shodan

        save_api_config(config_data)
        console.print("\n[bold green][+] Configuration saved successfully![/bold green]\n")
        sys.exit(0)

    # ═══════════════════════════════════════════════════════════════════════
    # تمرير الأوامر لـ CLI Handler
    # ═══════════════════════════════════════════════════════════════════════
    handle_cli_commands(args)


if __name__ == "__main__":
    main()
