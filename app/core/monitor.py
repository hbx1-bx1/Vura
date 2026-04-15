"""
VURA Ghost Monitor — Invisible Terminal Session Recording
══════════════════════════════════════════════════════════
Cross-platform terminal session recorder.
- macOS / Linux: uses the `script` command
- Windows: uses PowerShell `Start-Transcript`
Session data is cleaned and passed to AI for analysis.
"""

import os
import subprocess
import re
import datetime
import platform
import shutil
import signal
from pathlib import Path
from rich.console import Console
from app.utils.logger import log

console = Console()

IS_WIN = os.name == "nt"
_PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()
_DATA_DIR     = _PROJECT_ROOT / "data"
LOG_FILE      = _DATA_DIR / ".vura_session.log"
META_FILE     = _DATA_DIR / ".vura_session_meta.json"


def clean_ansi_escape_sequences(text):
    """حذف ANSI escape codes من النص — ألوان Terminal وحركات المؤشر."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    cleaned = ansi_escape.sub('', text)
    # حذف أحرف التحكم (backspace, carriage return, etc.)
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', cleaned)
    return cleaned


def _save_session_meta(action):
    """حفظ بيانات الجلسة الوصفية."""
    import json
    meta = {
        "action": action,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "shell": os.environ.get("SHELL", os.environ.get("COMSPEC", "unknown")),
        "os": platform.system(),
        "cwd": os.getcwd(),
    }
    try:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(META_FILE, "w") as f:
            json.dump(meta, f, indent=2)
    except Exception:
        pass


def _get_session_size():
    """حجم ملف الجلسة الحالي."""
    if LOG_FILE.exists():
        size = LOG_FILE.stat().st_size
        if size < 1024:
            return f"{size} bytes"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.1f} MB"
    return "0 bytes"


def _start_windows_transcript(silent=False):
    """
    Windows Ghost Monitor using PowerShell Start-Transcript.
    Opens a new PowerShell window that records everything to LOG_FILE.
    """
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    log_path_str = str(LOG_FILE)

    # PowerShell script: start transcript, inform user, wait for exit
    ps_commands = (
        f"Start-Transcript -Path '{log_path_str}' -Append; "
        "Write-Host '[VURA Ghost Monitor] Recording... Type exit when done.' -ForegroundColor Green; "
        "& $env:COMSPEC; "
        "Stop-Transcript"
    )

    if not silent:
        if LOG_FILE.exists():
            size = _get_session_size()
            console.print(f"\n[bold cyan][+] Resuming previous VURA Ghost Session ({size})...[/bold cyan]")
        else:
            console.print(f"\n[bold green][+] Starting new VURA Ghost Monitor (Windows)...[/bold green]")
        console.print("[bold yellow][!] A PowerShell window will open. Type [bold red]'exit'[/bold red] to stop recording.[/bold yellow]\n")

    _save_session_meta("start")
    log.info("Ghost Monitor started (Windows PowerShell Transcript)")

    try:
        subprocess.run(
            ["powershell", "-NoExit", "-Command", ps_commands],
            creationflags=subprocess.CREATE_NEW_CONSOLE if IS_WIN else 0,
        )

        if not silent:
            size = _get_session_size()
            console.print(f"\n[bold cyan][~] Session Paused & Saved safely! ({size})[/bold cyan]")
            console.print("[dim white]Run 'vura -H' to resume, or 'vura -R' to generate report.[/dim white]\n")

        _save_session_meta("pause")
        log.info("Ghost Monitor paused (Windows)", size=_get_session_size())

    except FileNotFoundError:
        if not silent:
            console.print("[bold red][!] PowerShell not found. Please install PowerShell 5.1+.[/bold red]")
        log.error("PowerShell not found on Windows")
    except KeyboardInterrupt:
        if not silent:
            console.print("\n[bold yellow][~] Session interrupted by user.[/bold yellow]")
        log.info("Ghost Monitor interrupted by user (Windows)")
    except Exception as e:
        if not silent:
            console.print(f"[bold red][!] Error during monitoring: {e}[/bold red]")
        log.exception("Ghost Monitor error (Windows)", e)


def start_ghost_monitor(silent=False):
    """
    بدء تسجيل Terminal session.

    Parameters:
        silent : True = بدون أي طباعة — للتشغيل التلقائي
    """
    sys_os = platform.system()

    # ── Windows: PowerShell Start-Transcript ──
    if IS_WIN:
        _start_windows_transcript(silent)
        return

    # ── macOS / Linux: script command ──
    user_shell = os.environ.get("SHELL", "/bin/bash")

    if not shutil.which("script"):
        if not silent:
            console.print("[bold red][!] 'script' command not found. Install 'util-linux' (Linux) or use a supported OS.[/bold red]")
        log.error("script command not found")
        return

    _DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not silent:
        if LOG_FILE.exists():
            size = _get_session_size()
            console.print(f"\n[bold cyan][+] Resuming previous VURA Ghost Session ({size})...[/bold cyan]")
        else:
            console.print(f"\n[bold green][+] Starting new VURA Ghost Monitor...[/bold green]")
        console.print("[bold yellow][!] Session is recording. Type [bold red]'exit'[/bold red] to pause/save.[/bold yellow]\n")

    _save_session_meta("start")
    log.info("Ghost Monitor started", shell=user_shell, os=sys_os)

    if sys_os == "Darwin":
        command = ["script", "-q", "-a", str(LOG_FILE), user_shell]
    else:
        command = ["script", "-q", "-a", "-c", user_shell, str(LOG_FILE)]

    try:
        subprocess.run(command)

        if not silent:
            size = _get_session_size()
            console.print(f"\n[bold cyan][~] Session Paused & Saved safely! ({size})[/bold cyan]")
            console.print("[dim white]Run 'vura -H' to resume, or 'vura -R' to generate report.[/dim white]\n")

        _save_session_meta("pause")
        log.info("Ghost Monitor paused", size=_get_session_size())

    except FileNotFoundError:
        if not silent:
            console.print("[bold red][!] 'script' command not found on this system.[/bold red]")
        log.error("script command FileNotFoundError")
    except KeyboardInterrupt:
        if not silent:
            console.print("\n[bold yellow][~] Session interrupted by user.[/bold yellow]")
        log.info("Ghost Monitor interrupted by user")
    except Exception as e:
        if not silent:
            console.print(f"[bold red][!] Error during monitoring: {e}[/bold red]")
        log.exception("Ghost Monitor error", e)


def end_ghost_monitor():
    """
    إيقاف الـ Ghost Monitor واستخراج البيانات النظيفة.

    Returns:
        str : البيانات المُنظّفة من ANSI codes — جاهزة للـ AI
        None : إذا لم تكن هناك جلسة نشطة
    """
    if not LOG_FILE.exists():
        console.print("[bold red][!] No active session found. Run 'vura -H' first.[/bold red]")
        log.warn("end_ghost_monitor called but no session file found")
        return None

    try:
        raw_data = LOG_FILE.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        console.print(f"[bold red][!] Cannot read session file: {e}[/bold red]")
        log.error("Cannot read session file", error=str(e))
        return None

    clean_data = clean_ansi_escape_sequences(raw_data)

    # ── حذف الملف ──
    try:
        LOG_FILE.unlink()
    except Exception:
        pass

    # ── حذف الـ meta ──
    try:
        if META_FILE.exists():
            META_FILE.unlink()
    except Exception:
        pass

    char_count = len(clean_data)
    console.print(f"[bold green][+] Captured {char_count:,} characters for the final report![/bold green]")
    log.info("Ghost Monitor ended", chars=char_count)

    _save_session_meta("end")

    if char_count < 10:
        console.print("[bold yellow][!] Warning: Very short session. Report may be empty.[/bold yellow]")
        log.warn("Very short session captured", chars=char_count)

    return clean_data


def is_session_active():
    """هل يوجد session نشطة حالياً."""
    return LOG_FILE.exists()


def get_session_info():
    """معلومات عن الجلسة الحالية."""
    if not LOG_FILE.exists():
        return None

    info = {"size": _get_session_size(), "path": str(LOG_FILE)}

    if META_FILE.exists():
        import json
        try:
            with open(META_FILE, "r") as f:
                info.update(json.load(f))
        except Exception:
            pass

    return info


def discard_session():
    """حذف الجلسة بدون توليد تقرير."""
    deleted = False
    for f in [LOG_FILE, META_FILE]:
        try:
            if f.exists():
                f.unlink()
                deleted = True
        except Exception:
            pass

    if deleted:
        console.print("[yellow][-] Session discarded.[/yellow]")
        log.info("Session discarded by user")
    else:
        console.print("[dim]No active session to discard.[/dim]")


# ═══════════════════════════════════════════════════════════════════════════════
# HOOKALL — Record ALL Open Terminals Simultaneously
# ═══════════════════════════════════════════════════════════════════════════════

HOOKALL_LOG    = _DATA_DIR / ".vura_hookall.log"
HOOKALL_PIDS   = _DATA_DIR / ".vura_hookall_pids"
EXCLUDE_FILE   = _DATA_DIR / ".vura_exclude_pts"


def _get_current_pts():
    """الحصول على مسار الـ pts للطرفية الحالية."""
    if IS_WIN:
        # Windows: no tty concept; return a pseudo-identifier
        try:
            pid = os.getpid()
            return f"WIN-PID-{pid}"
        except Exception:
            return None
    try:
        return subprocess.check_output(["tty"], text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None


def _get_active_terminals():
    """
    اكتشاف كل الطرفيات النشطة للمستخدم الحالي.
    - Windows: uses psutil to find cmd.exe / powershell.exe / pwsh.exe
    - macOS/Linux: uses `who` command + /dev/pts fallback
    """
    terminals = []

    if IS_WIN:
        # Windows: find interactive console host processes
        try:
            import psutil
            WIN_SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe"}
            for proc in psutil.process_iter(["pid", "name", "status"]):
                try:
                    info = proc.info
                    pname = (info.get("name") or "").lower()
                    if pname in WIN_SHELLS and info.get("status") != "zombie":
                        terminals.append(f"WIN-PID-{info['pid']}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except ImportError:
            pass
        return sorted(set(terminals))

    # macOS / Linux
    user = os.environ.get("USER", os.environ.get("LOGNAME", ""))

    try:
        output = subprocess.check_output(["who"], text=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                if user and parts[0] != user:
                    continue
                pts_name = parts[1]
                pts_path = f"/dev/{pts_name}"
                if Path(pts_path).exists():
                    terminals.append(pts_path)
    except Exception:
        pass

    # fallback: البحث في /dev/pts/ مباشرة
    if not terminals:
        pts_dir = Path("/dev/pts")
        try:
            if pts_dir.is_dir():
                for entry in pts_dir.iterdir():
                    if entry.name.isdigit() and os.access(entry, os.R_OK):
                        terminals.append(str(entry))
        except Exception:
            pass

    return sorted(set(terminals))


def _load_excluded():
    """تحميل قائمة الطرفيات المستبعدة."""
    if EXCLUDE_FILE.exists():
        try:
            return {line.strip() for line in EXCLUDE_FILE.read_text().splitlines() if line.strip()}
        except Exception:
            pass
    return set()


def exclude_terminal():
    """
    استبعاد الطرفية الحالية من hookall.
    الأمر: vura -e
    """
    pts = _get_current_pts()
    if not pts or "not a tty" in pts:
        console.print("[bold red][!] Cannot detect current terminal. Are you in a TTY?[/bold red]")
        return

    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    excluded = _load_excluded()
    excluded.add(pts)

    EXCLUDE_FILE.write_text("\n".join(sorted(excluded)) + "\n")

    console.print(f"[bold yellow][-] Terminal excluded: {pts}[/bold yellow]")
    console.print("[dim]This terminal will NOT be recorded by hookall.[/dim]")
    log.info("Terminal excluded from hookall", pts=pts)


def start_hookall(silent=False):
    """
    بدء تسجيل جميع الطرفيات المفتوحة في النظام.
    الأمر: vura -Ha

    يعمل عن طريق:
    1. اكتشاف كل الـ pts النشطة
    2. استبعاد الطرفيات المُعلّمة بـ -e
    3. تشغيل عملية قراءة خلفية لكل طرفية
    4. تجميع كل المخرجات في ملف واحد
    """
    _DATA_DIR.mkdir(parents=True, exist_ok=True)

    # ── اكتشاف الطرفيات ──
    all_terminals = _get_active_terminals()
    if not all_terminals:
        if not silent:
            console.print("[bold red][!] No active terminals found.[/bold red]")
        return

    # ── استبعاد المُعلَّمة ──
    excluded = _load_excluded()
    current_pts = _get_current_pts()
    if current_pts:
        excluded.add(current_pts)

    targets = [t for t in all_terminals if t not in excluded]

    if not targets:
        if not silent:
            console.print("[bold yellow][!] All terminals are excluded. Nothing to record.[/bold yellow]")
            console.print(f"[dim]Found: {len(all_terminals)} | Excluded: {len(excluded)}[/dim]")
        return

    if not silent:
        console.print(f"\n[bold green][+] VURA Hookall — Recording {len(targets)} terminal(s)...[/bold green]")
        for t in targets:
            console.print(f"    [cyan]→ {t}[/cyan]")
        if excluded:
            console.print(f"    [dim]Excluded: {len(excluded)} terminal(s)[/dim]")
        console.print(f"\n[bold yellow][!] Recording in background. Run 'vura -R' to stop and generate report.[/bold yellow]\n")

    # ── تشغيل القراءة الخلفية ──
    pids = []
    try:
        log_handle = open(HOOKALL_LOG, "a", encoding="utf-8", errors="ignore")

        for pts_id in targets:
            try:
                if IS_WIN:
                    # Windows: cannot `cat` a PID — skip background attach
                    # (Windows hookall is handled in the GUI via psutil snapshot)
                    continue
                proc = subprocess.Popen(
                    ["cat", pts_id],
                    stdout=log_handle,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=os.setpgrp,
                )
                pids.append(str(proc.pid))
                if not silent:
                    console.print(f"    [dim]PID {proc.pid} → {pts_id}[/dim]")
            except Exception as e:
                if not silent:
                    console.print(f"    [dim red]Cannot attach to {pts_id}: {e}[/dim red]")

        HOOKALL_PIDS.write_text("\n".join(pids))
        log.info("Hookall started", terminals=len(targets), pids=len(pids))

    except Exception as e:
        if not silent:
            console.print(f"[bold red][!] Hookall failed: {e}[/bold red]")
        log.error("Hookall start failed", error=str(e))


def stop_hookall():
    """
    إيقاف hookall وإرجاع البيانات المجمّعة.
    يُستدعى من end_ghost_monitor إذا كان hookall نشطاً.
    """
    # ── إيقاف العمليات الخلفية ──
    if HOOKALL_PIDS.exists():
        try:
            pids = [p.strip() for p in HOOKALL_PIDS.read_text().splitlines() if p.strip()]

            for pid in pids:
                try:
                    pid_int = int(pid)
                    if IS_WIN:
                        os.kill(pid_int, signal.SIGTERM)
                    else:
                        os.kill(pid_int, 9)  # SIGKILL
                except (ProcessLookupError, ValueError, PermissionError):
                    pass

            HOOKALL_PIDS.unlink()
            console.print(f"[bold cyan][~] Hookall stopped ({len(pids)} recorder(s) terminated).[/bold cyan]")
        except Exception:
            pass

    # ── قراءة البيانات المجمّعة ──
    if HOOKALL_LOG.exists():
        try:
            raw_data = HOOKALL_LOG.read_text(encoding="utf-8", errors="ignore")
            clean_data = clean_ansi_escape_sequences(raw_data)
            HOOKALL_LOG.unlink()

            console.print(f"[bold green][+] Hookall captured {len(clean_data):,} characters from all terminals![/bold green]")
            log.info("Hookall ended", chars=len(clean_data))
            return clean_data
        except Exception:
            pass

    return None


def is_hookall_active():
    """هل hookall يعمل حالياً."""
    return HOOKALL_PIDS.exists()


def clear_excluded():
    """مسح قائمة الطرفيات المستبعدة."""
    if EXCLUDE_FILE.exists():
        EXCLUDE_FILE.unlink()
        console.print("[green][+] Exclude list cleared.[/green]")
