"""
VURA Recon Engine — Automated Reconnaissance & Attack Surface Mapping
═══════════════════════════════════════════════════════════════════════
Runs external recon tools (Amass, Shodan, theHarvester, Nmap, Whois)
and aggregates results into a unified format for AI analysis.

Dependencies:
    - requests (in requirements.txt)
    - External tools: amass, theharvester, nmap, whois (installed on Kali Linux)

Usage:
    from app.core.recon import run_full_recon, run_amass, run_shodan
    results = run_full_recon("example.com", shodan_key="YOUR_KEY")
    # results → string ready for ai_engine.generate_report(results, scan_type="recon")
"""

import os
import json
import shutil
import subprocess
import datetime
import platform
import requests
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

IS_WIN = os.name == "nt"

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Timeout بالثواني لكل أداة — بعض الأدوات تأخذ وقت طويل
TOOL_TIMEOUTS = {
    "amass":        600,    # 10 دقائق — Amass enum بطيء بطبيعته
    "theharvester": 300,    # 5 دقائق
    "nmap":         600,    # 10 دقائق — يعتمد على عدد البورتات
    "whois":        30,     # 30 ثانية — سريع
    "shodan":       60,     # دقيقة — API call
}

# Shodan API
SHODAN_API_BASE = "https://api.shodan.io"

# ─── مسار حفظ نتائج الاستطلاع ───────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()
_RECON_DIR    = _PROJECT_ROOT / "data" / "recon"


# ═══════════════════════════════════════════════════════════════════════════════
# TOOL AVAILABILITY CHECK
# ═══════════════════════════════════════════════════════════════════════════════

def check_tool(tool_name):
    """
    فحص إذا الأداة مثبّتة على النظام.
    يرجع المسار الكامل أو None.
    """
    return shutil.which(tool_name)


def check_all_tools():
    """
    فحص كل أدوات الاستطلاع المدعومة.
    يرجع dict: {tool_name: path_or_None}
    """
    tools = ["amass", "theHarvester", "nmap", "whois"]
    status = {}
    for tool in tools:
        path = check_tool(tool)
        status[tool] = path
    return status


def show_tool_status():
    """عرض حالة الأدوات في Terminal بشكل جميل."""
    from rich.table import Table

    status = check_all_tools()
    table = Table(title="VURA Recon — Tool Availability", show_header=True, header_style="bold magenta")
    table.add_column("Tool", style="bold cyan")
    table.add_column("Status")
    table.add_column("Path", style="dim")

    for tool, path in status.items():
        if path:
            table.add_row(tool, "[green]Installed ✔[/green]", path)
        else:
            if IS_WIN:
                hint = _win_install_hint(tool)
            else:
                hint = f"Install with: apt install {tool}"
            table.add_row(tool, "[red]Not Found ✘[/red]", hint)

    table.add_row("Shodan API", "[yellow]Requires API Key[/yellow]", "Set shodan_api_key in config.json")
    console.print(table)
    return status


def _win_install_hint(tool_name):
    """Return Windows-specific install instructions for recon tools."""
    hints = {
        "amass":          "Download from: https://github.com/owasp-amass/amass/releases",
        "theHarvester":   "pip install theHarvester",
        "nmap":           "Download from: https://nmap.org/download.html#windows",
        "whois":          "Install via: choco install whois  OR  winget install SysInternals.WhoIs",
    }
    return hints.get(tool_name, f"Search for '{tool_name}' Windows installer")


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def _run_command(cmd, tool_name, timeout=None):
    """
    تشغيل أمر subprocess مع timeout وerror handling موحّد.
    يرجع (stdout, stderr, success).
    """
    timeout = timeout or TOOL_TIMEOUTS.get(tool_name, 120)

    if not check_tool(cmd[0]):
        if IS_WIN:
            hint = _win_install_hint(cmd[0])
            return "", f"[NOT INSTALLED] '{cmd[0]}' not found on Windows. {hint}", False
        return "", f"[NOT INSTALLED] '{cmd[0]}' not found. Install it first.", False

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "HOME": os.path.expanduser("~")},
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode != 0 and not stdout:
            return "", f"[ERROR] {cmd[0]} exited with code {result.returncode}: {stderr}", False

        return stdout, stderr, True

    except subprocess.TimeoutExpired:
        return "", f"[TIMEOUT] {cmd[0]} exceeded {timeout}s timeout. Try a smaller scope.", False
    except FileNotFoundError:
        return "", f"[NOT FOUND] '{cmd[0]}' is not installed on this system.", False
    except PermissionError:
        return "", f"[PERMISSION] Cannot execute '{cmd[0]}'. Try: chmod +x $(which {cmd[0]})", False
    except Exception as e:
        return "", f"[ERROR] {cmd[0]} failed: {str(e)}", False


def _save_recon_output(domain, tool_name, content):
    """حفظ مخرجات كل أداة في data/recon/ للمراجعة لاحقاً."""
    try:
        _RECON_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = domain.replace(".", "_").replace("/", "_")
        filename = _RECON_DIR / f"{safe_domain}_{tool_name}_{timestamp}.txt"
        filename.write_text(content, encoding="utf-8")
        return str(filename)
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# RECON TOOLS
# ═══════════════════════════════════════════════════════════════════════════════

def run_amass(domain, passive_only=True, timeout=None):
    """
    تشغيل Amass لاكتشاف الـ Subdomains.

    Parameters:
        domain       : الدومين المستهدف (e.g., "example.com")
        passive_only : True = passive فقط (أسرع وأخفى), False = active enum
        timeout      : timeout بالثواني (افتراضي 600)

    Returns:
        dict: {"tool": "amass", "domain": ..., "success": bool,
               "subdomains": [...], "raw_output": str, "error": str}
    """
    console.print(f"[bold cyan][~] VURA Recon: Running Amass {'(passive)' if passive_only else '(active)'} on {domain}...[/bold cyan]")

    cmd = ["amass", "enum"]
    if passive_only:
        cmd.append("-passive")
    cmd.extend(["-d", domain])

    stdout, stderr, success = _run_command(cmd, "amass", timeout)

    result = {
        "tool": "amass",
        "domain": domain,
        "success": success,
        "subdomains": [],
        "raw_output": stdout,
        "error": stderr if not success else "",
    }

    if success and stdout:
        # Amass يطبع subdomain واحد في كل سطر
        subdomains = [line.strip() for line in stdout.splitlines() if line.strip() and "." in line]
        result["subdomains"] = sorted(set(subdomains))
        console.print(f"[green]  ✓ Amass found {len(result['subdomains'])} subdomains[/green]")
        _save_recon_output(domain, "amass", stdout)
    elif not success:
        console.print(f"[dim red]  ✘ Amass: {stderr}[/dim red]")

    return result


def run_theharvester(domain, source="all", limit=500, timeout=None):
    """
    تشغيل theHarvester لجمع emails و subdomains و IPs.

    Parameters:
        domain  : الدومين المستهدف
        source  : مصادر البحث ("all", "google", "bing", "linkedin", etc.)
        limit   : عدد النتائج الأقصى
        timeout : timeout بالثواني

    Returns:
        dict: {"tool": "theharvester", "domain": ..., "success": bool,
               "emails": [...], "hosts": [...], "ips": [...], "raw_output": str}
    """
    console.print(f"[bold cyan][~] VURA Recon: Running theHarvester on {domain} (source: {source})...[/bold cyan]")

    cmd = ["theHarvester", "-d", domain, "-b", source, "-l", str(limit)]

    stdout, stderr, success = _run_command(cmd, "theharvester", timeout)

    result = {
        "tool": "theharvester",
        "domain": domain,
        "success": success,
        "emails": [],
        "hosts": [],
        "ips": [],
        "raw_output": stdout,
        "error": stderr if not success else "",
    }

    if success and stdout:
        _parse_theharvester_output(stdout, result)
        total = len(result["emails"]) + len(result["hosts"]) + len(result["ips"])
        console.print(
            f"[green]  ✓ theHarvester found: "
            f"{len(result['emails'])} emails, "
            f"{len(result['hosts'])} hosts, "
            f"{len(result['ips'])} IPs[/green]"
        )
        _save_recon_output(domain, "theharvester", stdout)
    elif not success:
        console.print(f"[dim red]  ✘ theHarvester: {stderr}[/dim red]")

    return result


def _parse_theharvester_output(output, result):
    """تحليل مخرجات theHarvester واستخراج البيانات المنظّمة."""
    current_section = None

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
            result["emails"].append(line)
        elif current_section == "hosts" and "." in line:
            result["hosts"].append(line)
        elif current_section == "ips":
            # استخراج IP من السطر
            import re
            ip_match = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
            result["ips"].extend(ip_match)

    result["emails"] = sorted(set(result["emails"]))
    result["hosts"]  = sorted(set(result["hosts"]))
    result["ips"]    = sorted(set(result["ips"]))


def run_shodan(target, api_key=None, timeout=None):
    """
    استعلام Shodan API عن هدف (IP أو domain).

    Parameters:
        target  : IP address أو domain
        api_key : Shodan API key (إذا None يقرأ من config.json → shodan_api_key)

    Returns:
        dict: {"tool": "shodan", "target": ..., "success": bool,
               "ports": [...], "services": [...], "vulns": [...],
               "os": str, "org": str, "raw_output": str}
    """
    console.print(f"[bold cyan][~] VURA Recon: Querying Shodan for {target}...[/bold cyan]")

    # ── تحميل API key ──
    if not api_key:
        try:
            from app.utils.config import load_api_config
            config = load_api_config() or {}
            api_key = config.get("shodan_api_key", "").strip()
        except Exception:
            pass

    if not api_key:
        msg = "Shodan API key not provided. Set 'shodan_api_key' in config.json or pass it directly."
        console.print(f"[dim red]  ✘ {msg}[/dim red]")
        return {
            "tool": "shodan", "target": target, "success": False,
            "ports": [], "services": [], "vulns": [],
            "os": "", "org": "", "raw_output": "", "error": msg,
        }

    timeout = timeout or TOOL_TIMEOUTS.get("shodan", 60)

    result = {
        "tool": "shodan", "target": target, "success": False,
        "ports": [], "services": [], "vulns": [],
        "os": "", "org": "", "raw_output": "", "error": "",
    }

    try:
        # ── تحديد إذا كان IP أو domain ──
        import re
        is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target))

        if is_ip:
            url = f"{SHODAN_API_BASE}/shodan/host/{target}?key={api_key}"
        else:
            # DNS resolve أولاً ثم host lookup
            dns_url = f"{SHODAN_API_BASE}/dns/resolve?hostnames={target}&key={api_key}"
            dns_resp = requests.get(dns_url, timeout=timeout)
            dns_resp.raise_for_status()
            dns_data = dns_resp.json()

            resolved_ip = dns_data.get(target)
            if not resolved_ip:
                result["error"] = f"Shodan could not resolve '{target}' to an IP."
                console.print(f"[dim red]  ✘ {result['error']}[/dim red]")
                return result

            url = f"{SHODAN_API_BASE}/shodan/host/{resolved_ip}?key={api_key}"
            result["resolved_ip"] = resolved_ip

        # ── استعلام Host ──
        resp = requests.get(url, timeout=timeout)

        if resp.status_code == 401:
            result["error"] = "Shodan API key is invalid (401). Check your key."
            console.print(f"[dim red]  ✘ {result['error']}[/dim red]")
            return result

        if resp.status_code == 404:
            result["error"] = f"No Shodan data found for '{target}'."
            result["success"] = True  # ليس خطأ — فقط لا توجد بيانات
            console.print(f"[dim yellow]  ~ No Shodan records for {target}[/dim yellow]")
            return result

        resp.raise_for_status()
        data = resp.json()

        # ── استخراج البيانات ──
        result["success"]    = True
        result["org"]        = data.get("org", "Unknown")
        result["os"]         = data.get("os") or "Unknown"
        result["ports"]      = data.get("ports", [])
        result["vulns"]      = list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", [])
        result["raw_output"] = json.dumps(data, indent=2, ensure_ascii=False)

        # ── استخراج services من data ──
        for service_data in data.get("data", []):
            svc = {
                "port":      service_data.get("port"),
                "transport": service_data.get("transport", "tcp"),
                "product":   service_data.get("product", ""),
                "version":   service_data.get("version", ""),
                "banner":    (service_data.get("data", ""))[:200],  # أول 200 حرف فقط
            }
            result["services"].append(svc)

        console.print(
            f"[green]  ✓ Shodan: {len(result['ports'])} ports, "
            f"{len(result['services'])} services, "
            f"{len(result['vulns'])} known vulns | Org: {result['org']}[/green]"
        )
        _save_recon_output(target, "shodan", result["raw_output"])

    except requests.exceptions.ConnectionError:
        result["error"] = "Cannot connect to Shodan API. Check your internet."
        console.print(f"[dim red]  ✘ {result['error']}[/dim red]")
    except requests.exceptions.Timeout:
        result["error"] = f"Shodan API timeout ({timeout}s). Try again."
        console.print(f"[dim red]  ✘ {result['error']}[/dim red]")
    except Exception as e:
        result["error"] = f"Shodan error: {str(e)}"
        console.print(f"[dim red]  ✘ {result['error']}[/dim red]")

    return result


def run_nmap(target, scan_type="default", ports=None, timeout=None):
    """
    تشغيل Nmap لمسح البورتات والخدمات.

    Parameters:
        target    : IP أو domain أو CIDR range
        scan_type : "default" (-sV), "quick" (-F), "full" (-sV -sC -A), "vuln" (--script vuln)
        ports     : بورتات محددة (e.g., "22,80,443" أو "1-1000")
        timeout   : timeout بالثواني

    Returns:
        dict: {"tool": "nmap", "target": ..., "success": bool,
               "raw_output": str, "error": str}
    """
    console.print(f"[bold cyan][~] VURA Recon: Running Nmap ({scan_type}) on {target}...[/bold cyan]")

    # ── بناء الأمر حسب نوع المسح ──
    cmd = ["nmap"]

    if scan_type == "quick":
        cmd.extend(["-F", "-sV"])
    elif scan_type == "full":
        cmd.extend(["-sV", "-sC", "-A", "-T4"])
    elif scan_type == "vuln":
        cmd.extend(["-sV", "--script", "vuln", "-T4"])
    else:  # default
        cmd.extend(["-sV", "-T4"])

    if ports:
        cmd.extend(["-p", ports])

    cmd.append(target)

    stdout, stderr, success = _run_command(cmd, "nmap", timeout)

    result = {
        "tool": "nmap",
        "target": target,
        "scan_type": scan_type,
        "success": success,
        "raw_output": stdout,
        "error": stderr if not success else "",
    }

    if success and stdout:
        # عدّ البورتات المفتوحة من الـ output
        open_ports = [line for line in stdout.splitlines() if "/tcp" in line and "open" in line]
        console.print(f"[green]  ✓ Nmap: {len(open_ports)} open ports detected[/green]")
        _save_recon_output(target, "nmap", stdout)
    elif not success:
        console.print(f"[dim red]  ✘ Nmap: {stderr}[/dim red]")

    return result


def run_whois(domain, timeout=None):
    """
    تشغيل Whois lookup على domain.

    Returns:
        dict: {"tool": "whois", "domain": ..., "success": bool,
               "raw_output": str, "error": str}
    """
    console.print(f"[bold cyan][~] VURA Recon: Running WHOIS on {domain}...[/bold cyan]")

    stdout, stderr, success = _run_command(["whois", domain], "whois", timeout)

    result = {
        "tool": "whois",
        "domain": domain,
        "success": success,
        "raw_output": stdout,
        "error": stderr if not success else "",
    }

    if success and stdout:
        console.print(f"[green]  ✓ WHOIS data retrieved ({len(stdout)} chars)[/green]")
        _save_recon_output(domain, "whois", stdout)
    elif not success:
        console.print(f"[dim red]  ✘ WHOIS: {stderr}[/dim red]")

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# AGGREGATION — تجميع كل النتائج في format واحد للـ AI
# ═══════════════════════════════════════════════════════════════════════════════

def aggregate_results(*results):
    """
    تجميع نتائج كل أدوات الاستطلاع في string واحد منظّم.
    هذا الـ string يُمرَّر مباشرة لـ ai_engine.generate_report(data, scan_type="recon").

    Parameters:
        *results : أي عدد من dicts المرجعة من run_amass, run_shodan, etc.

    Returns:
        str : نص منظّم يحتوي كل النتائج — جاهز للتحليل بالـ AI
    """
    if not results:
        return ""

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sections = []

    sections.append("=" * 70)
    sections.append(f"VURA RECONNAISSANCE REPORT — Aggregated Results")
    sections.append(f"Generated: {timestamp}")
    sections.append("=" * 70)

    # ── تجميع كل الـ subdomains و emails و IPs من كل الأدوات ──
    all_subdomains = set()
    all_emails     = set()
    all_ips        = set()
    all_ports      = set()
    all_vulns      = set()

    for res in results:
        if not isinstance(res, dict):
            continue

        tool = res.get("tool", "unknown")
        target = res.get("domain", res.get("target", "unknown"))
        success = res.get("success", False)

        sections.append(f"\n{'─' * 70}")
        sections.append(f"TOOL: {tool.upper()}")
        sections.append(f"TARGET: {target}")
        sections.append(f"STATUS: {'SUCCESS' if success else 'FAILED'}")
        sections.append(f"{'─' * 70}")

        if not success:
            error = res.get("error", "Unknown error")
            sections.append(f"Error: {error}")
            continue

        # ── Amass ──
        if tool == "amass":
            subs = res.get("subdomains", [])
            all_subdomains.update(subs)
            sections.append(f"\nSubdomains Discovered: {len(subs)}")
            for sub in subs:
                sections.append(f"  - {sub}")

        # ── theHarvester ──
        elif tool == "theharvester":
            emails = res.get("emails", [])
            hosts  = res.get("hosts", [])
            ips    = res.get("ips", [])
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

        # ── Shodan ──
        elif tool == "shodan":
            org    = res.get("org", "")
            os_str = res.get("os", "")
            ports  = res.get("ports", [])
            svcs   = res.get("services", [])
            vulns  = res.get("vulns", [])
            all_ports.update(str(p) for p in ports)
            all_vulns.update(vulns)

            if org:
                sections.append(f"\nOrganization: {org}")
            if os_str:
                sections.append(f"Operating System: {os_str}")
            if ports:
                sections.append(f"\nOpen Ports: {', '.join(str(p) for p in sorted(ports))}")
            if svcs:
                sections.append(f"\nServices Detected:")
                for svc in svcs:
                    port    = svc.get("port", "?")
                    proto   = svc.get("transport", "tcp")
                    product = svc.get("product", "unknown")
                    version = svc.get("version", "")
                    banner  = svc.get("banner", "")[:100]
                    sections.append(f"  - Port {port}/{proto}: {product} {version}")
                    if banner:
                        sections.append(f"    Banner: {banner}")
            if vulns:
                sections.append(f"\nKnown Vulnerabilities (Shodan): {len(vulns)}")
                for v in vulns:
                    sections.append(f"  - {v}")

        # ── Nmap ──
        elif tool == "nmap":
            raw = res.get("raw_output", "")
            if raw:
                sections.append(f"\nNmap Scan Results:")
                sections.append(raw)

        # ── WHOIS ──
        elif tool == "whois":
            raw = res.get("raw_output", "")
            if raw:
                sections.append(f"\nWHOIS Data:")
                sections.append(raw)

        # ── أي أداة أخرى ──
        else:
            raw = res.get("raw_output", "")
            if raw:
                sections.append(f"\nRaw Output:")
                sections.append(raw)

    # ── ملخص مجمّع ──
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


# ═══════════════════════════════════════════════════════════════════════════════
# FULL RECON — تشغيل كل الأدوات دفعة واحدة
# ═══════════════════════════════════════════════════════════════════════════════

def run_full_recon(domain, shodan_key=None, nmap_target=None, nmap_scan="default",
                   skip_amass=False, skip_theharvester=False, skip_shodan=False,
                   skip_nmap=False, skip_whois=False):
    """
    تشغيل كل أدوات الاستطلاع المتاحة على هدف واحد.

    Parameters:
        domain            : الدومين المستهدف (e.g., "example.com")
        shodan_key        : Shodan API key (اختياري — يقرأ من config إذا None)
        nmap_target       : هدف Nmap إذا مختلف عن domain (e.g., IP address)
        nmap_scan         : نوع مسح Nmap: "default", "quick", "full", "vuln"
        skip_*            : True = تخطي الأداة

    Returns:
        str : نتائج مجمّعة جاهزة لـ ai_engine.generate_report(data, scan_type="recon")
    """
    console.print(f"\n[bold green]{'═' * 60}[/bold green]")
    console.print(f"[bold green]  VURA Full Reconnaissance — Target: {domain}[/bold green]")
    console.print(f"[bold green]{'═' * 60}[/bold green]\n")

    results = []

    # ── 1. WHOIS ──
    if not skip_whois:
        results.append(run_whois(domain))
    else:
        console.print("[dim]  ⊘ Skipping WHOIS[/dim]")

    # ── 2. Amass ──
    if not skip_amass:
        results.append(run_amass(domain))
    else:
        console.print("[dim]  ⊘ Skipping Amass[/dim]")

    # ── 3. theHarvester ──
    if not skip_theharvester:
        results.append(run_theharvester(domain))
    else:
        console.print("[dim]  ⊘ Skipping theHarvester[/dim]")

    # ── 4. Shodan ──
    if not skip_shodan:
        results.append(run_shodan(domain, api_key=shodan_key))
    else:
        console.print("[dim]  ⊘ Skipping Shodan[/dim]")

    # ── 5. Nmap ──
    if not skip_nmap:
        nmap_t = nmap_target or domain
        results.append(run_nmap(nmap_t, scan_type=nmap_scan))
    else:
        console.print("[dim]  ⊘ Skipping Nmap[/dim]")

    # ── تجميع النتائج ──
    successful = sum(1 for r in results if r.get("success"))
    total = len(results)
    console.print(f"\n[bold magenta]  ✓ Recon complete: {successful}/{total} tools succeeded[/bold magenta]\n")

    aggregated = aggregate_results(*results)

    # حفظ النتائج المجمّعة
    _save_recon_output(domain, "FULL_RECON", aggregated)

    return aggregated
