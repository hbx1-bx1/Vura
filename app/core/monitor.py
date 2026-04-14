"""
VURA Ghost Monitor — Invisible Terminal Session Recording
══════════════════════════════════════════════════════════
Uses the `script` command to silently record terminal sessions.
Supports Linux and macOS. Session data is cleaned and passed to AI.
"""

import os
import subprocess
import re
import datetime
import platform
import shutil
from rich.console import Console
from app.utils.logger import log

console = Console()

# ✅ FIX #4 — مسارات مطلقة
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DATA_DIR     = os.path.join(_PROJECT_ROOT, "data")
LOG_FILE      = os.path.join(_DATA_DIR, ".vura_session.log")
META_FILE     = os.path.join(_DATA_DIR, ".vura_session_meta.json")


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
        "shell": os.environ.get("SHELL", "unknown"),
        "os": platform.system(),
        "cwd": os.getcwd(),
    }
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        with open(META_FILE, "w") as f:
            json.dump(meta, f, indent=2)
    except Exception:
        pass


def _get_session_size():
    """حجم ملف الجلسة الحالي."""
    if os.path.exists(LOG_FILE):
        size = os.path.getsize(LOG_FILE)
        if size < 1024:
            return f"{size} bytes"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.1f} MB"
    return "0 bytes"


def start_ghost_monitor(silent=False):
    """
    بدء تسجيل Terminal session.

    Parameters:
        silent : True = بدون أي طباعة — للتشغيل التلقائي
    """
    user_shell = os.environ.get("SHELL", "/bin/bash")
    sys_os = platform.system()

    # ── فحص النظام ──
    if sys_os == "Windows":
        if not silent:
            console.print("[bold red][!] Ghost Monitor is not supported on Windows.[/bold red]")
            console.print("[dim white]Tip: Use Windows Terminal's built-in logging or WSL.[/dim white]\n")
        log.warn("Ghost Monitor attempted on Windows")
        return

    if not shutil.which("script"):
        if not silent:
            console.print("[bold red][!] 'script' command not found. Install 'util-linux' (Linux) or use a supported OS.[/bold red]")
        log.error("script command not found")
        return

    # ── إعداد المجلد ──
    os.makedirs(_DATA_DIR, exist_ok=True)

    if not silent:
        if os.path.exists(LOG_FILE):
            size = _get_session_size()
            console.print(f"\n[bold cyan][+] Resuming previous VURA Ghost Session ({size})...[/bold cyan]")
        else:
            console.print(f"\n[bold green][+] Starting new VURA Ghost Monitor...[/bold green]")
        console.print("[bold yellow][!] Session is recording. Type [bold red]'exit'[/bold red] to pause/save.[/bold yellow]\n")

    _save_session_meta("start")
    log.info("Ghost Monitor started", shell=user_shell, os=sys_os)

    # ── تحديد الأمر حسب النظام ──
    if sys_os == "Darwin":
        command = ["script", "-q", "-a", LOG_FILE, user_shell]
    else:
        command = ["script", "-q", "-a", "-c", user_shell, LOG_FILE]

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
    if not os.path.exists(LOG_FILE):
        console.print("[bold red][!] No active session found. Run 'vura -H' first.[/bold red]")
        log.warn("end_ghost_monitor called but no session file found")
        return None

    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            raw_data = f.read()
    except Exception as e:
        console.print(f"[bold red][!] Cannot read session file: {e}[/bold red]")
        log.error("Cannot read session file", error=str(e))
        return None

    clean_data = clean_ansi_escape_sequences(raw_data)

    # ── حذف الملف ──
    try:
        os.remove(LOG_FILE)
    except Exception:
        pass

    # ── حذف الـ meta ──
    try:
        if os.path.exists(META_FILE):
            os.remove(META_FILE)
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
    return os.path.exists(LOG_FILE)


def get_session_info():
    """معلومات عن الجلسة الحالية."""
    if not os.path.exists(LOG_FILE):
        return None

    info = {"size": _get_session_size(), "path": LOG_FILE}

    if os.path.exists(META_FILE):
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
        if os.path.exists(f):
            try:
                os.remove(f)
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

HOOKALL_LOG    = os.path.join(_DATA_DIR, ".vura_hookall.log")
HOOKALL_PIDS   = os.path.join(_DATA_DIR, ".vura_hookall_pids")
EXCLUDE_FILE   = os.path.join(_DATA_DIR, ".vura_exclude_pts")


def _get_current_pts():
    """الحصول على مسار الـ pts للطرفية الحالية."""
    try:
        return subprocess.check_output(["tty"], text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None


def _get_active_terminals():
    """
    اكتشاف كل الطرفيات النشطة للمستخدم الحالي.
    يستخدم أمر `who` لمعرفة كل الجلسات.
    """
    user = os.environ.get("USER", os.environ.get("LOGNAME", ""))
    terminals = []

    try:
        output = subprocess.check_output(["who"], text=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                # فحص إذا هذا المستخدم الحالي
                if user and parts[0] != user:
                    continue
                pts_name = parts[1]
                pts_path = f"/dev/{pts_name}"
                if os.path.exists(pts_path):
                    terminals.append(pts_path)
    except Exception:
        pass

    # fallback: البحث في /dev/pts/ مباشرة
    if not terminals:
        try:
            pts_dir = "/dev/pts"
            if os.path.isdir(pts_dir):
                for entry in os.listdir(pts_dir):
                    if entry.isdigit():
                        pts_path = os.path.join(pts_dir, entry)
                        # فحص الصلاحية — هل نقدر نقرأ منه
                        if os.access(pts_path, os.R_OK):
                            terminals.append(pts_path)
        except Exception:
            pass

    return sorted(set(terminals))


def _load_excluded():
    """تحميل قائمة الطرفيات المستبعدة."""
    if os.path.exists(EXCLUDE_FILE):
        try:
            with open(EXCLUDE_FILE, "r") as f:
                return {line.strip() for line in f if line.strip()}
        except Exception:
            pass
    return set()


def exclude_terminal():
    """
    استبعاد الطرفية الحالية من hookall.
    الأمر: vura -e
    """
    sys_os = platform.system()
    if sys_os == "Windows":
        console.print("[bold red][!] Not supported on Windows.[/bold red]")
        return

    pts = _get_current_pts()
    if not pts or "not a tty" in pts:
        console.print("[bold red][!] Cannot detect current terminal. Are you in a TTY?[/bold red]")
        return

    os.makedirs(_DATA_DIR, exist_ok=True)
    excluded = _load_excluded()
    excluded.add(pts)

    with open(EXCLUDE_FILE, "w") as f:
        for p in sorted(excluded):
            f.write(p + "\n")

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
    sys_os = platform.system()
    if sys_os == "Windows":
        if not silent:
            console.print("[bold red][!] Hookall is not supported on Windows.[/bold red]")
        return

    os.makedirs(_DATA_DIR, exist_ok=True)

    # ── اكتشاف الطرفيات ──
    all_terminals = _get_active_terminals()
    if not all_terminals:
        if not silent:
            console.print("[bold red][!] No active terminals found.[/bold red]")
        return

    # ── استبعاد المُعلَّمة ──
    excluded = _load_excluded()
    current_pts = _get_current_pts()
    # استبعاد الطرفية الحالية تلقائياً (لا نقرأ من نفسنا)
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
        # فتح ملف اللوج للكتابة
        log_handle = open(HOOKALL_LOG, "a", encoding="utf-8", errors="ignore")

        for pts_path in targets:
            try:
                # كل طرفية: نقرأ مخرجاتها في الخلفية
                proc = subprocess.Popen(
                    ["cat", pts_path],
                    stdout=log_handle,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=os.setpgrp,  # منع إنهاء العملية عند إغلاق الطرفية الحالية
                )
                pids.append(str(proc.pid))
                if not silent:
                    console.print(f"    [dim]PID {proc.pid} → {pts_path}[/dim]")
            except Exception as e:
                if not silent:
                    console.print(f"    [dim red]Cannot attach to {pts_path}: {e}[/dim red]")

        # حفظ الـ PIDs لإيقافها لاحقاً
        with open(HOOKALL_PIDS, "w") as f:
            f.write("\n".join(pids))

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
    if os.path.exists(HOOKALL_PIDS):
        try:
            with open(HOOKALL_PIDS, "r") as f:
                pids = [p.strip() for p in f.readlines() if p.strip()]

            for pid in pids:
                try:
                    os.kill(int(pid), 9)  # SIGKILL
                except (ProcessLookupError, ValueError, PermissionError):
                    pass

            os.remove(HOOKALL_PIDS)
            console.print(f"[bold cyan][~] Hookall stopped ({len(pids)} recorder(s) terminated).[/bold cyan]")
        except Exception:
            pass

    # ── قراءة البيانات المجمّعة ──
    if os.path.exists(HOOKALL_LOG):
        try:
            with open(HOOKALL_LOG, "r", encoding="utf-8", errors="ignore") as f:
                raw_data = f.read()
            clean_data = clean_ansi_escape_sequences(raw_data)
            os.remove(HOOKALL_LOG)

            console.print(f"[bold green][+] Hookall captured {len(clean_data):,} characters from all terminals![/bold green]")
            log.info("Hookall ended", chars=len(clean_data))
            return clean_data
        except Exception:
            pass

    return None


def is_hookall_active():
    """هل hookall يعمل حالياً."""
    return os.path.exists(HOOKALL_PIDS)


def clear_excluded():
    """مسح قائمة الطرفيات المستبعدة."""
    if os.path.exists(EXCLUDE_FILE):
        os.remove(EXCLUDE_FILE)
        console.print("[green][+] Exclude list cleared.[/green]")
