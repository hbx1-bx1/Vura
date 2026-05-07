"""
VURA Recon Engine — Phase 4 (Parallel + Async)
═══════════════════════════════════════════════════════════════════════════
Runs external recon tools in parallel using concurrent.futures.
Supports per-tool progress tracking for GUI integration.

Key improvements over sequential:
  - Tools run concurrently via ThreadPoolExecutor
  - Per-tool progress callbacks for GUI progress bars
  - Graceful error handling — one tool failure doesn't stop others
  - Results aggregated in completion order

Usage:
    from app.core.recon import run_full_recon_parallel

    results, summary = run_full_recon_parallel(
        "example.com",
        progress_callback=lambda tool, status: print(f"{tool}: {status}"),
    )
"""

import os
import re
import json
import shutil
import subprocess
import datetime
import platform
import threading
import requests
from pathlib import Path
from typing import Optional, Callable, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

IS_WIN = os.name == "nt"

# ── Timeouts (seconds) ──────────────────────────────────────────────
TOOL_TIMEOUTS = {
    "amass":        600,
    "theharvester": 300,
    "nmap":         600,
    "whois":        30,
    "shodan":       60,
}

# ── Shodan API ──────────────────────────────────────────────────────
SHODAN_API_BASE = "https://api.shodan.io"

# ── Recon output directory ──────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()
_RECON_DIR = _PROJECT_ROOT / "data" / "recon"


# ══════════════════════════════════════════════════════════════════════
# Data Classes
# ══════════════════════════════════════════════════════════════════════

@dataclass
class ToolResult:
    """Result from a single recon tool execution."""
    tool: str
    target: str
    success: bool
    raw_output: str = ""
    error: str = ""
    duration: float = 0.0
    extra: dict = field(default_factory=dict)


@dataclass
class ReconProgress:
    """Progress update for a single tool."""
    tool: str
    status: str       # "starting" | "running" | "done" | "failed" | "skipped"
    message: str = ""
    result: Optional[ToolResult] = None


# ══════════════════════════════════════════════════════════════════════
# Tool Availability
# ══════════════════════════════════════════════════════════════════════

def check_tool(tool_name: str) -> Optional[str]:
    """Check if a tool is installed. Returns path or None."""
    return shutil.which(tool_name)


def check_all_tools() -> dict:
    """Check all recon tools. Returns {tool_name: path_or_None}."""
    tools = ["amass", "theHarvester", "nmap", "whois"]
    return {tool: check_tool(tool) for tool in tools}


def show_tool_status():
    """Display tool availability in a Rich table."""
    from rich.table import Table
    status = check_all_tools()
    table = Table(
        title="VURA Recon — Tool Availability",
        show_header=True, header_style="bold magenta",
    )
    table.add_column("Tool", style="bold cyan")
    table.add_column("Status")
    table.add_column("Path", style="dim")

    for tool, path in status.items():
        if path:
            table.add_row(tool, "[green]Installed ✔[/green]", path)
        else:
            hint = _win_install_hint(tool) if IS_WIN else f"Install: apt install {tool}"
            table.add_row(tool, "[red]Not Found ✘[/red]", hint)

    table.add_row("Shodan API", "[yellow]Requires API Key[/yellow]",
                  "Set shodan_api_key in config.json")
    console.print(table)
    return status


def _win_install_hint(tool_name: str) -> str:
    """Windows-specific install instructions."""
    hints = {
        "amass":          "Download: https://github.com/owasp-amass/amass/releases",
        "theHarvester":   "pip install theHarvester",
        "nmap":           "Download: https://nmap.org/download.html#windows",
        "whois":          "choco install whois  OR  winget install SysInternals.WhoIs",
    }
    return hints.get(tool_name, f"Search for '{tool_name}' Windows installer")


# ══════════════════════════════════════════════════════════════════════
# Command Runner
# ══════════════════════════════════════════════════════════════════════

def _run_command(cmd: list, tool_name: str,
                 timeout: Optional[int] = None) -> tuple[str, str, bool]:
    """
    Run a subprocess command with timeout and error handling.
    Returns (stdout, stderr, success).
    """
    timeout = timeout or TOOL_TIMEOUTS.get(tool_name, 120)

    if not check_tool(cmd[0]):
        hint = _win_install_hint(cmd[0]) if IS_WIN else ""
        return "", f"[NOT INSTALLED] '{cmd[0]}' not found. {hint}", False

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "HOME": os.path.expanduser("~")},
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode != 0 and not stdout:
            return "", (
                f"[ERROR] {cmd[0]} exited with code {result.returncode}: {stderr}"
            ), False

        return stdout, stderr, True

    except subprocess.TimeoutExpired:
        return "", (
            f"[TIMEOUT] {cmd[0]} exceeded {timeout}s. Try a smaller scope."
        ), False
    except FileNotFoundError:
        return "", f"[NOT FOUND] '{cmd[0]}' is not installed.", False
    except PermissionError:
        return "", f"[PERMISSION] Cannot execute '{cmd[0]}'.", False
    except Exception as e:
        return "", f"[ERROR] {cmd[0]} failed: {e}", False


def _save_recon_output(domain: str, tool_name: str, content: str) -> Optional[str]:
    """Save recon output to data/recon/."""
    try:
        _RECON_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = domain.replace(".", "_").replace("/", "_")
        filename = _RECON_DIR / f"{safe}_{tool_name}_{timestamp}.txt"
        filename.write_text(content, encoding="utf-8")
        return str(filename)
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════
# Individual Tool Functions
# ══════════════════════════════════════════════════════════════════════

def run_amass(domain: str, passive_only: bool = True,
              timeout: Optional[int] = None) -> ToolResult:
    """Run Amass for subdomain enumeration."""
    start = datetime.datetime.now()
    cmd = ["amass", "enum"]
    if passive_only:
        cmd.append("-passive")
    cmd.extend(["-d", domain])

    stdout, stderr, success = _run_command(cmd, "amass", timeout)
    duration = (datetime.datetime.now() - start).total_seconds()

    result = ToolResult(
        tool="amass", target=domain, success=success,
        raw_output=stdout, error=stderr if not success else "",
        duration=duration,
    )

    if success and stdout:
        subs = sorted(set(
            line.strip() for line in stdout.splitlines()
            if line.strip() and "." in line
        ))
        result.extra["subdomains"] = subs
        result.extra["count"] = len(subs)
        _save_recon_output(domain, "amass", stdout)

    return result


def run_theharvester(domain: str, source: str = "all",
                     limit: int = 500,
                     timeout: Optional[int] = None) -> ToolResult:
    """Run theHarvester for emails, hosts, IPs."""
    start = datetime.datetime.now()
    cmd = ["theHarvester", "-d", domain, "-b", source, "-l", str(limit)]

    stdout, stderr, success = _run_command(cmd, "theharvester", timeout)
    duration = (datetime.datetime.now() - start).total_seconds()

    result = ToolResult(
        tool="theharvester", target=domain, success=success,
        raw_output=stdout, error=stderr if not success else "",
        duration=duration,
    )

    if success and stdout:
        _parse_theharvester(stdout, result.extra)
        _save_recon_output(domain, "theharvester", stdout)

    return result


def _parse_theharvester(output: str, extra: dict) -> None:
    """Parse theHarvester output into structured data."""
    current_section = None
    emails, hosts, ips = [], [], []

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("*") or line.startswith("="):
            continue

        lower = line.lower()
        if "emails found" in lower or "emails:" in lower:
            current_section = "emails"
            continue
        elif "hosts found" in lower or "hosts:" in lower:
            current_section = "hosts"
            continue
        elif "ips found" in lower or "ip addresses" in lower:
            current_section = "ips"
            continue
        elif "---" in line or "===" in line:
            continue

        if current_section == "emails" and "@" in line:
            emails.append(line)
        elif current_section == "hosts" and "." in line:
            hosts.append(line)
        elif current_section == "ips":
            ip_match = re.findall(
                r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line
            )
            ips.extend(ip_match)

    extra["emails"] = sorted(set(emails))
    extra["hosts"] = sorted(set(hosts))
    extra["ips"] = sorted(set(ips))


def run_shodan(target: str, api_key: Optional[str] = None,
               timeout: Optional[int] = None) -> ToolResult:
    """Query Shodan API for a target (IP or domain)."""
    start = datetime.datetime.now()

    if not api_key:
        try:
            from app.utils.config import load_api_config
            config = load_api_config() or {}
            api_key = config.get("shodan_api_key", "").strip()
        except Exception:
            pass

    timeout = timeout or TOOL_TIMEOUTS.get("shodan", 60)

    if not api_key:
        duration = (datetime.datetime.now() - start).total_seconds()
        return ToolResult(
            tool="shodan", target=target, success=False,
            error="Shodan API key not set in config.json",
            duration=duration,
        )

    result = ToolResult(tool="shodan", target=target, success=False,
                        duration=0.0)

    try:
        is_ip = bool(re.match(
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target
        ))

        if is_ip:
            url = f"{SHODAN_API_BASE}/shodan/host/{target}"
        else:
            dns_resp = requests.get(
                f"{SHODAN_API_BASE}/dns/resolve",
                params={"hostnames": target, "key": api_key},
                timeout=timeout,
            )
            dns_resp.raise_for_status()
            dns_data = dns_resp.json()
            resolved_ip = dns_data.get(target)
            if not resolved_ip:
                result.error = f"Shodan could not resolve '{target}'"
                result.duration = (
                    datetime.datetime.now() - start
                ).total_seconds()
                return result
            url = f"{SHODAN_API_BASE}/shodan/host/{resolved_ip}"
            result.extra["resolved_ip"] = resolved_ip

        resp = requests.get(
            url, params={"key": api_key}, timeout=timeout,
        )

        if resp.status_code == 401:
            result.error = "Shodan API key is invalid (401)"
        elif resp.status_code == 404:
            result.error = f"No Shodan data for '{target}'"
            result.success = True
        else:
            resp.raise_for_status()
            data = resp.json()

            result.success = True
            result.extra["org"] = data.get("org", "Unknown")
            result.extra["os"] = data.get("os") or "Unknown"
            result.extra["ports"] = data.get("ports", [])
            result.extra["vulns"] = (
                list(data.get("vulns", {}).keys())
                if isinstance(data.get("vulns"), dict)
                else data.get("vulns", [])
            )
            result.raw_output = json.dumps(
                data, indent=2, ensure_ascii=False
            )

            for svc_data in data.get("data", []):
                result.extra.setdefault("services", []).append({
                    "port": svc_data.get("port"),
                    "transport": svc_data.get("transport", "tcp"),
                    "product": svc_data.get("product", ""),
                    "version": svc_data.get("version", ""),
                    "banner": (svc_data.get("data", ""))[:200],
                })

            _save_recon_output(target, "shodan", result.raw_output)

    except requests.exceptions.ConnectionError:
        result.error = "Cannot connect to Shodan API"
    except requests.exceptions.Timeout:
        result.error = f"Shodan API timeout ({timeout}s)"
    except Exception as e:
        result.error = f"Shodan error: {e}"

    result.duration = (datetime.datetime.now() - start).total_seconds()
    return result


def run_nmap(target: str, scan_type: str = "default",
             ports: Optional[str] = None,
             timeout: Optional[int] = None) -> ToolResult:
    """Run Nmap port and service scan."""
    start = datetime.datetime.now()

    cmd = ["nmap"]
    if scan_type == "quick":
        cmd.extend(["-F", "-sV"])
    elif scan_type == "full":
        cmd.extend(["-sV", "-sC", "-A", "-T4"])
    elif scan_type == "vuln":
        cmd.extend(["-sV", "--script", "vuln", "-T4"])
    else:
        cmd.extend(["-sV", "-T4"])

    if ports:
        cmd.extend(["-p", ports])
    cmd.append(target)

    stdout, stderr, success = _run_command(cmd, "nmap", timeout)
    duration = (datetime.datetime.now() - start).total_seconds()

    result = ToolResult(
        tool="nmap", target=target, success=success,
        raw_output=stdout, error=stderr if not success else "",
        duration=duration,
        extra={"scan_type": scan_type},
    )

    if success and stdout:
        open_ports = [
            line for line in stdout.splitlines()
            if "/tcp" in line and "open" in line
        ]
        result.extra["open_ports"] = len(open_ports)
        _save_recon_output(target, "nmap", stdout)

    return result


def run_whois(domain: str,
              timeout: Optional[int] = None) -> ToolResult:
    """Run WHOIS lookup on a domain."""
    start = datetime.datetime.now()
    stdout, stderr, success = _run_command(
        ["whois", domain], "whois", timeout
    )
    duration = (datetime.datetime.now() - start).total_seconds()

    result = ToolResult(
        tool="whois", target=domain, success=success,
        raw_output=stdout, error=stderr if not success else "",
        duration=duration,
    )

    if success and stdout:
        _save_recon_output(domain, "whois", stdout)

    return result


# ══════════════════════════════════════════════════════════════════════
# Parallel Execution Engine
# ══════════════════════════════════════════════════════════════════════

# Tool execution registry — maps tool name to (func, kwargs_builder)
TOOL_REGISTRY = {
    "whois":        (run_whois,        lambda d, **kw: {}),
    "amass":        (run_amass,        lambda d, **kw: {"passive_only": kw.get("passive", True)}),
    "theharvester": (run_theharvester, lambda d, **kw: {"source": "all", "limit": 500}),
    "shodan":       (run_shodan,       lambda d, **kw: {"api_key": kw.get("shodan_key")}),
    "nmap":         (run_nmap,         lambda d, **kw: {
                        "scan_type": kw.get("nmap_scan", "default"),
                        "ports": kw.get("nmap_ports"),
                    }),
}

# Priority order for execution (whois is fastest, amass slowest)
# Parallel execution ignores this order, but it's used for CLI display
TOOL_DISPLAY_ORDER = ["whois", "shodan", "amass", "theharvester", "nmap"]


def run_full_recon_parallel(
    domain: str,
    shodan_key: Optional[str] = None,
    nmap_target: Optional[str] = None,
    nmap_scan: str = "default",
    nmap_ports: Optional[str] = None,
    passive: bool = True,
    skip_amass: bool = False,
    skip_theharvester: bool = False,
    skip_shodan: bool = False,
    skip_nmap: bool = False,
    skip_whois: bool = False,
    max_workers: int = 5,
    progress_callback: Optional[Callable[[ReconProgress], None]] = None,
) -> tuple[list[ToolResult], dict]:
    """
    Run all recon tools in parallel and aggregate results.

    Parameters:
        domain            : Target domain
        shodan_key        : Shodan API key (reads from config if None)
        nmap_target       : Nmap target (uses domain if None)
        nmap_scan         : Nmap scan type
        nmap_ports        : Specific ports for Nmap
        passive           : Passive-only Amass
        skip_*            : Skip specific tools
        max_workers       : Max concurrent threads
        progress_callback : Called with ReconProgress for each tool

    Returns:
        Tuple of (list of ToolResult, summary dict)
    """
    start_time = datetime.datetime.now()

    # Build tool list
    tools_to_run = []
    skip_map = {
        "whois":        skip_whois,
        "amass":        skip_amass,
        "theharvester": skip_theharvester,
        "shodan":       skip_shodan,
        "nmap":         skip_nmap,
    }

    kw = {
        "shodan_key": shodan_key,
        "nmap_scan": nmap_scan,
        "nmap_ports": nmap_ports,
        "passive": passive,
    }

    for tool_name in TOOL_DISPLAY_ORDER:
        if skip_map.get(tool_name, False):
            if progress_callback:
                progress_callback(ReconProgress(
                    tool=tool_name, status="skipped",
                    message="Skipped by user",
                ))
            continue
        tools_to_run.append((tool_name, kw))

    if not tools_to_run:
        return [], {"total": 0, "success": 0, "failed": 0, "skipped": 5,
                     "duration": 0.0}

    # ── Execute in parallel ──────────────────────────────────────────
    results: list[ToolResult] = []
    skipped = 5 - len(tools_to_run)

    def _execute(tool_name: str, tool_kw: dict) -> ToolResult:
        """Execute a single tool and report progress."""
        target = nmap_target if tool_name == "nmap" else domain

        if progress_callback:
            progress_callback(ReconProgress(
                tool=tool_name, status="starting",
                message=f"Starting {tool_name} on {target}",
            ))

        func, kwargs_builder = TOOL_REGISTRY[tool_name]
        func_kw = kwargs_builder(target, **tool_kw)

        result = func(target, **func_kw)

        if progress_callback:
            status = "done" if result.success else "failed"
            msg = result.error if not result.success else (
                f"Completed in {result.duration:.1f}s"
            )
            progress_callback(ReconProgress(
                tool=tool_name, status=status, message=msg,
                result=result,
            ))

        return result

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_execute, name, kw): name
            for name, kw in tools_to_run
        }

        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                tool_name = futures[future]
                results.append(ToolResult(
                    tool=tool_name, target=domain,
                    success=False, error=str(e),
                ))
                if progress_callback:
                    progress_callback(ReconProgress(
                        tool=tool_name, status="failed",
                        message=str(e),
                    ))

    # ── Sort results by display order ────────────────────────────────
    order_map = {name: i for i, name in enumerate(TOOL_DISPLAY_ORDER)}
    results.sort(key=lambda r: order_map.get(r.tool, 99))

    duration = (datetime.datetime.now() - start_time).total_seconds()
    success_count = sum(1 for r in results if r.success)

    summary = {
        "total": len(results),
        "success": success_count,
        "failed": len(results) - success_count,
        "skipped": skipped,
        "duration": round(duration, 1),
    }

    return results, summary


# ══════════════════════════════════════════════════════════════════════
# CLI-Compatible Wrapper (backward compatible with old run_full_recon)
# ══════════════════════════════════════════════════════════════════════

def run_full_recon(
    domain: str,
    shodan_key: Optional[str] = None,
    nmap_target: Optional[str] = None,
    nmap_scan: str = "default",
    skip_amass: bool = False,
    skip_theharvester: bool = False,
    skip_shodan: bool = False,
    skip_nmap: bool = False,
    skip_whois: bool = False,
) -> str:
    """
    Run full recon with parallel execution.
    Backward compatible — returns aggregated string for AI analysis.

    Displays Rich progress bars for each tool.
    """
    console.print(
        f"\n[bold green]{'═' * 60}[/bold green]"
    )
    console.print(
        f"[bold green]  VURA Full Reconnaissance — Target: {domain}[/bold green]"
    )
    console.print(
        f"[bold green]{'═' * 60}[/bold green]\n"
    )

    results, summary = run_full_recon_parallel(
        domain,
        shodan_key=shodan_key,
        nmap_target=nmap_target,
        nmap_scan=nmap_scan,
        skip_amass=skip_amass,
        skip_theharvester=skip_theharvester,
        skip_shodan=skip_shodan,
        skip_nmap=skip_nmap,
        skip_whois=skip_whois,
        progress_callback=_cli_progress,
    )

    console.print(
        f"\n[bold magenta]  ✓ Recon complete: "
        f"{summary['success']}/{summary['total']} tools succeeded "
        f"({summary['duration']}s)[/bold magenta]\n"
    )

    aggregated = aggregate_results(*results)
    _save_recon_output(domain, "FULL_RECON", aggregated)

    return aggregated


def _cli_progress(progress: ReconProgress) -> None:
    """CLI progress callback using Rich."""
    icon = {
        "starting": "[cyan]⏳[/cyan]",
        "running":  "[yellow]⚙[/yellow]",
        "done":     "[green]✔[/green]",
        "failed":   "[red]✘[/red]",
        "skipped":  "[dim]⊘[/dim]",
    }.get(progress.status, " ")

    tool_label = f"[bold]{progress.tool:>14}[/bold]"
    console.print(f"  {icon} {tool_label}  {progress.message}")


# ══════════════════════════════════════════════════════════════════════
# Aggregation (unchanged from sequential version)
# ══════════════════════════════════════════════════════════════════════

def aggregate_results(*results: ToolResult) -> str:
    """Aggregate ToolResult objects into a formatted string for AI analysis."""
    if not results:
        return ""

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sections = []

    sections.append("=" * 70)
    sections.append("VURA RECONNAISSANCE REPORT — Aggregated Results")
    sections.append(f"Generated: {timestamp}")
    sections.append("=" * 70)

    all_subdomains: set = set()
    all_emails: set = set()
    all_ips: set = set()
    all_ports: set = set()
    all_vulns: set = set()

    for res in results:
        tool = res.tool
        target = res.target
        success = res.success
        extra = res.extra

        sections.append(f"\n{'─' * 70}")
        sections.append(f"TOOL: {tool.upper()}")
        sections.append(f"TARGET: {target}")
        sections.append(f"STATUS: {'SUCCESS' if success else 'FAILED'}")
        sections.append(f"DURATION: {res.duration:.1f}s")
        sections.append(f"{'─' * 70}")

        if not success:
            sections.append(f"Error: {res.error}")
            continue

        if tool == "amass":
            subs = extra.get("subdomains", [])
            all_subdomains.update(subs)
            sections.append(f"\nSubdomains Discovered: {len(subs)}")
            for sub in subs:
                sections.append(f"  - {sub}")

        elif tool == "theharvester":
            emails = extra.get("emails", [])
            hosts = extra.get("hosts", [])
            ips = extra.get("ips", [])
            all_emails.update(emails)
            all_subdomains.update(hosts)
            all_ips.update(ips)

            if emails:
                sections.append(f"\nEmails Found: {len(emails)}")
                for email in emails:
                    sections.append(f"  - {email}")
            if hosts:
                sections.append(f"\nHosts Found: {len(hosts)}")
                for host in hosts:
                    sections.append(f"  - {host}")
            if ips:
                sections.append(f"\nIP Addresses: {len(ips)}")
                for ip in ips:
                    sections.append(f"  - {ip}")

        elif tool == "shodan":
            org = extra.get("org", "")
            os_str = extra.get("os", "")
            ports = extra.get("ports", [])
            svcs = extra.get("services", [])
            vulns = extra.get("vulns", [])
            all_ports.update(str(p) for p in ports)
            all_vulns.update(vulns)

            if org:
                sections.append(f"\nOrganization: {org}")
            if os_str:
                sections.append(f"Operating System: {os_str}")
            if ports:
                sections.append(
                    f"\nOpen Ports: "
                    f"{', '.join(str(p) for p in sorted(ports))}"
                )
            if svcs:
                sections.append(f"\nServices Detected:")
                for svc in svcs:
                    port = svc.get("port", "?")
                    proto = svc.get("transport", "tcp")
                    product = svc.get("product", "unknown")
                    version = svc.get("version", "")
                    banner = svc.get("banner", "")[:100]
                    sections.append(
                        f"  - Port {port}/{proto}: {product} {version}"
                    )
                    if banner:
                        sections.append(f"    Banner: {banner}")
            if vulns:
                sections.append(
                    f"\nKnown Vulnerabilities (Shodan): {len(vulns)}"
                )
                for v in vulns:
                    sections.append(f"  - {v}")

        elif tool == "nmap":
            raw = res.raw_output
            if raw:
                sections.append(f"\nNmap Scan Results:")
                sections.append(raw)

        elif tool == "whois":
            raw = res.raw_output
            if raw:
                sections.append(f"\nWHOIS Data:")
                sections.append(raw)

    # ── Summary ──────────────────────────────────────────────────────
    sections.append(f"\n{'=' * 70}")
    sections.append("AGGREGATED SUMMARY")
    sections.append(f"{'=' * 70}")
    sections.append(f"Total Unique Subdomains: {len(all_subdomains)}")
    sections.append(f"Total Unique Emails:     {len(all_emails)}")
    sections.append(f"Total Unique IPs:        {len(all_ips)}")
    sections.append(f"Total Unique Open Ports:  {len(all_ports)}")
    sections.append(f"Total Known CVEs:        {len(all_vulns)}")

    if all_vulns:
        sections.append(f"\nAll CVEs Found:")
        for v in sorted(all_vulns):
            sections.append(f"  - {v}")

    return "\n".join(sections)
