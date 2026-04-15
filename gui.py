"""
VURA Desktop GUI v3 — Full CLI Coverage
════════════════════════════════════════
Every CLI command accessible from GUI.
Ghost Monitor opens a real terminal.
HookAll reads all open sessions.
Bilingual EN/AR. Flet 0.82 compatible.
"""
import sys, os

# ── Force UTF-8 on Windows (fixes emoji crash in legacy terminals) ──
if sys.stdout and sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and sys.stderr.encoding != 'utf-8':
    sys.stderr.reconfigure(encoding='utf-8')

import flet as ft
import glob, json, datetime, threading, traceback
import subprocess, shutil, platform, re, signal
from pathlib import Path

_ROOT = Path(__file__).parent.absolute()
if str(_ROOT) not in sys.path: sys.path.insert(0, str(_ROOT))
_DATA = _ROOT / "data"
_LOG  = _DATA / ".vura_session.log"

# ── Colors ──
C = type('C', (), dict(
    T="#1abc9c", T2="#16a085", N="#1a1a2e", N2="#22223a", N3="#2a2a4a",
    S="#16213e", S2="#1e2d50", CD="#0f3460", DM="#8899aa", R="#e74c3c",
    O="#f39c12", G="#2ecc71", Y="#f1c40f", W="#ffffff", BG="#0a0a1a",
))()

VER = "1.0.0"
RTYPES = {
    "1": {"n":"Network Scan",     "a":"فحص الشبكة",   "i":"🌐", "c":"Network — ports, services, firewalls."},
    "2": {"n":"Web Application",  "a":"تطبيق ويب",    "i":"🕸️",  "c":"Web — XSS, SQLi, CSRF, headers."},
    "3": {"n":"Recon / OSINT",    "a":"استطلاع",       "i":"🔍", "c":"Recon — subdomains, emails, services."},
    "4": {"n":"Vuln Assessment",  "a":"تقييم ثغرات",   "i":"🛡️",  "c":"Vulnerability assessment — CVSS."},
    "5": {"n":"Custom",           "a":"مخصّص",         "i":"📝", "c":""},
}
LANGS = ["English","Arabic","French","Spanish","German","Japanese","Chinese",
         "Korean","Russian","Portuguese","Italian","Turkish","Dutch","Hindi"]

# ═══════════════════════════════════════════════════════════════
# i18n
# ═══════════════════════════════════════════════════════════════
L = {
 "home":{"e":"Home","a":"الرئيسية"},"monitor":{"e":"Monitor","a":"المراقب"},
 "analyze":{"e":"Analyze","a":"تحليل"},"recon":{"e":"Recon","a":"استطلاع"},
 "reports":{"e":"Reports","a":"التقارير"},"settings":{"e":"Settings","a":"الإعدادات"},
 "sub":{"e":"Vulnerability Reporting AI","a":"ذكاء اصطناعي لتقارير الثغرات"},
 "syst":{"e":"System Status","a":"حالة النظام"},
 "ai":{"e":"AI Engine:","a":"محرك الذكاء:"},
 "nocfg":{"e":"Not Configured","a":"غير مُعدّ"},
 "reps":{"e":"Reports","a":"تقارير"},
 "idle":{"e":"Idle","a":"خامل"},"actv":{"e":"Active","a":"نشط"},
 "nosess":{"e":"No active session","a":"لا توجد جلسة"},
 "rec":{"e":"Recording...","a":"جارٍ التسجيل..."},
 "qact":{"e":"Quick Actions","a":"إجراءات سريعة"},
 "uchk":{"e":"Unable to check","a":"تعذّر الفحص"},
 # ── Monitor ──
 "ghost":{"e":"Ghost Monitor","a":"المراقب الشبحي"},
 "sesst":{"e":"Session Status","a":"حالة الجلسة"},
 "start_ghost":{"e":"Start Ghost (-H)","a":"بدء المراقب (-H)"},
 "start_hookall":{"e":"HookAll (-Ha)","a":"تسجيل شامل (-Ha)"},
 "exclude":{"e":"Exclude This (-e)","a":"استبعاد هذه (-e)"},
 "silent_mode":{"e":"Silent Mode","a":"وضع صامت"},
 "stop_report":{"e":"Stop & Report (-R)","a":"إيقاف وتقرير (-R)"},
 "stop_collect":{"e":"Stop & Collect","a":"إيقاف وجمع"},
 "discard":{"e":"Discard","a":"حذف"},
 "out":{"e":"Output","a":"المخرجات"},
 "how":{"e":"How It Works","a":"كيف يعمل"},
 "how_txt":{
   "e":"Start Ghost (-H): Opens a terminal with recording enabled.\n"
       "HookAll (-Ha): Reads ALL open terminal sessions.\n"
       "Exclude (-e): Excludes current terminal from HookAll.\n"
       "Stop & Report (-R): Stops recording → generates AI report.\n"
       "Stop & Collect: Stops recording → saves data for Analyze page.\n\n"
       "Workflow:\n"
       "  1. Click 'Start Ghost' → terminal opens\n"
       "  2. Work inside it (nmap, nikto, sqlmap...)\n"
       "  3. Close terminal or click 'Stop & Collect'\n"
       "  4. Go to Analyze → Generate Report",
   "a":"بدء المراقب (-H): يفتح طرفية مع تسجيل.\n"
       "تسجيل شامل (-Ha): يقرأ كل الطرفيات المفتوحة.\n"
       "استبعاد (-e): يستبعد الطرفية الحالية من التسجيل الشامل.\n"
       "إيقاف وتقرير (-R): يوقف التسجيل ← يولّد تقرير AI.\n"
       "إيقاف وجمع: يوقف التسجيل ← يحفظ للتحليل.\n\n"
       "الخطوات:\n"
       "  1. اضغط 'بدء المراقب' ← تفتح طرفية\n"
       "  2. اشتغل داخلها\n"
       "  3. أغلقها أو اضغط 'إيقاف وجمع'\n"
       "  4. اذهب للتحليل ← ولّد التقرير",
 },
 "stop_msg":{"e":"Stopping...","a":"جارٍ الإيقاف..."},
 "capt":{"e":"✔ Captured {n} chars. Go to Analyze.","a":"✔ التقاط {n} حرف. اذهب للتحليل."},
 "nosf":{"e":"No session data.","a":"لا بيانات جلسة."},
 "disc":{"e":"Session discarded.","a":"تم حذف الجلسة."},
 "noterm":{"e":"No terminal found! Install: sudo apt install xterm","a":"لا طرفية! ثبّت: sudo apt install xterm"},
 "hookall_reading":{"e":"Reading all open terminals...","a":"جارٍ قراءة كل الطرفيات..."},
 "hookall_done":{"e":"✔ HookAll: Collected {n} chars from {t} terminals.","a":"✔ تم جمع {n} حرف من {t} طرفية."},
 "hookall_none":{"e":"No open terminal sessions found.","a":"لا توجد طرفيات مفتوحة."},
 "excluded":{"e":"Terminal excluded from HookAll.","a":"تم استبعاد الطرفية."},
 # ── Analyze ──
 "anly":{"e":"Analyze & Generate Report","a":"تحليل وتوليد تقرير"},
 "man":{"e":"Manual Input (-m)","a":"إدخال يدوي (-m)"},
 "file":{"e":"File (-f)","a":"ملف (-f)"},
 "gdata":{"e":"Ghost Data","a":"بيانات المراقب"},
 "hist":{"e":"History (-p)","a":"السجل (-p)"},
 "paste":{"e":"Paste terminal output...","a":"الصق مخرجات الطرفية..."},
 "fpath":{"e":"File path (e.g. /home/user/scan.log)","a":"مسار الملف"},
 "hlines":{"e":"Lines","a":"أسطر"},
 "rtype":{"e":"Report Type","a":"نوع التقرير"},
 "fmt":{"e":"Format (-F)","a":"الصيغة (-F)"},
 "lang":{"e":"Language (-l)","a":"اللغة (-l)"},
 "appr":{"e":"Approach (-A)","a":"المنهج (-A)"},
 "defense":{"e":"Defense","a":"دفاعي"},
 "offense":{"e":"Offense","a":"هجومي"},
 "stype":{"e":"Scan Type (-S)","a":"نوع الفحص (-S)"},
 "notify":{"e":"Telegram (-n)","a":"تيليجرام (-n)"},
 "gen":{"e":"Generate Report","a":"توليد التقرير"},
 "cdesc":{"e":"Custom description","a":"وصف مخصّص"},
 "gening":{"e":"Generating...","a":"جارٍ التوليد..."},
 "rsaved":{"e":"Report saved:","a":"تم الحفظ:"},
 "rok":{"e":"Report generated!","a":"تم توليد التقرير!"},
 "rfail":{"e":"Failed","a":"فشل"},
 "nodata":{"e":"No data.","a":"لا بيانات."},
 "nogd":{"e":"No Ghost data.","a":"لا بيانات مراقب."},
 # ── Recon ──
 "rtitle":{"e":"Recon / OSINT (-r)","a":"استطلاع / OSINT (-r)"},
 "tstat":{"e":"Tools Status","a":"حالة الأدوات"},
 "tdom":{"e":"Target Domain","a":"النطاق المستهدف"},
 "skip":{"e":"Skip Tools:","a":"تخطّي أدوات:"},
 "rrun":{"e":"Run Recon","a":"بدء الاستطلاع"},
 "rout":{"e":"Recon Output","a":"مخرجات الاستطلاع"},
 "rrunning":{"e":"Running recon...","a":"جارٍ الاستطلاع..."},
 "rdone":{"e":"Done!","a":"اكتمل!"},
 "edom":{"e":"Enter domain","a":"أدخل نطاقاً"},
 # ── Reports ──
 "arch":{"e":"Reports Archive (-Hy)","a":"أرشيف التقارير (-Hy)"},
 "ref":{"e":"Refresh","a":"تحديث"},
 "opf":{"e":"Open Folder","a":"فتح المجلد"},
 "recreate":{"e":"Recreate Last (-Rc)","a":"إعادة الأخير (-Rc)"},
 "norep":{"e":"No reports.","a":"لا تقارير."},
 "sf":{"e":"{s} sessions, {f} files","a":"{s} جلسة، {f} ملف"},
 "selrep":{"e":"Select a report","a":"اختر تقريراً"},
 "rlist":{"e":"Sessions","a":"الجلسات"},
 "bin":{"e":"(Binary — can't preview)","a":"(ثنائي — لا يُعرض)"},
 "recreating":{"e":"Recreating last report...","a":"جارٍ إعادة التوليد..."},
 "recreate_ok":{"e":"Report recreated!","a":"تم إعادة التوليد!"},
 "recreate_no":{"e":"No cached data to recreate.","a":"لا بيانات محفوظة لإعادة التوليد."},
 # ── Settings ──
 "stitle":{"e":"Settings (-Ch)","a":"الإعدادات (-Ch)"},
 "prov":{"e":"Provider","a":"المزود"},"akey":{"e":"API Key","a":"مفتاح API"},
 "mname":{"e":"Model","a":"النموذج"},"curl":{"e":"Custom URL","a":"رابط مخصّص"},
 "tgn":{"e":"Telegram","a":"تيليجرام"},"tgt":{"e":"Bot Token","a":"توكن البوت"},
 "tgc":{"e":"Chat ID","a":"معرّف المحادثة"},
 "integ":{"e":"Integrations","a":"تكاملات"},
 "shk":{"e":"Shodan Key","a":"مفتاح Shodan"},
 "save":{"e":"Save","a":"حفظ"},
 "saved":{"e":"Saved!","a":"تم الحفظ!"},
 "uilang":{"e":"Interface Language","a":"لغة الواجهة"},
 # ── Diagnostics ──
 "diag":{"e":"Diagnostics (-Ck)","a":"التشخيص (-Ck)"},
 "drun":{"e":"Running...","a":"جارٍ..."},
 "ddone":{"e":"Done","a":"اكتمل"},
}

# ═══════════════════════════════════════════════════════════════
# GHOST MONITOR ENGINE (standalone, no dependency on monitor.py)
# ═══════════════════════════════════════════════════════════════
_ghost = {"pid": None, "silent": False}

IS_WIN = os.name == "nt"

def _find_term():
    """Cross-platform terminal detection."""
    if IS_WIN:
        # Windows — prefer Windows Terminal, fall back to PowerShell/cmd
        if shutil.which("wt"):
            return "wt"                # Windows Terminal
        if shutil.which("pwsh"):
            return "pwsh"              # PowerShell 7+
        if shutil.which("powershell"):
            return "powershell"        # Windows PowerShell 5.1
        return "cmd"                   # always available
    if platform.system() == "Darwin":
        if shutil.which("iTerm2") or Path("/Applications/iTerm.app").exists():
            return "iterm2"
        return "terminal.app"
    # Linux
    for t in ["qterminal","x-terminal-emulator","xfce4-terminal","gnome-terminal",
              "konsole","mate-terminal","lxterminal","xterm","terminator","alacritty","kitty"]:
        if shutil.which(t): return t
    return None

def _clean_ansi(text):
    text = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)

def _launch_terminal(cmd, term):
    """
    Cross-platform terminal launcher.
    Windows: opens PowerShell / Windows Terminal with command.
    macOS: uses osascript to open Terminal.app / iTerm2.
    Linux: uses detected terminal emulator.
    Returns (subprocess.Popen, terminal_name) or raises.
    """
    if IS_WIN:
        # Windows launchers
        if term == "wt":
            p = subprocess.Popen(["wt", "powershell", "-NoExit", "-Command", cmd],
                                creationflags=subprocess.CREATE_NEW_CONSOLE)
        elif term in ("pwsh", "powershell"):
            p = subprocess.Popen([term, "-NoExit", "-Command", cmd],
                                creationflags=subprocess.CREATE_NEW_CONSOLE)
        else:
            p = subprocess.Popen(["cmd", "/k", cmd],
                                creationflags=subprocess.CREATE_NEW_CONSOLE)
        return p, term

    if platform.system() == "Darwin":
        if term == "iterm2":
            ascript = (
                'tell application "iTerm"\n'
                '  activate\n'
                '  set newWindow to (create window with default profile)\n'
                f'  tell current session of newWindow\n'
                f'    write text "{cmd}"\n'
                '  end tell\n'
                'end tell'
            )
            p = subprocess.Popen(["osascript", "-e", ascript])
        else:
            ascript = (
                'tell application "Terminal"\n'
                '  activate\n'
                f'  do script "{cmd}"\n'
                'end tell'
            )
            p = subprocess.Popen(["osascript", "-e", ascript])
        return p, term

    # Linux terminal emulators
    if "gnome-terminal" in term:
        p = subprocess.Popen([term, "--title=VURA Ghost", "--", "bash", "-c", cmd])
    elif "konsole" in term:
        p = subprocess.Popen([term, "-e", "bash", "-c", cmd])
    elif "xterm" in term:
        p = subprocess.Popen([term, "-T", "VURA Ghost", "-e", f"bash -c '{cmd}'"])
    else:
        p = subprocess.Popen([term, "-e", f"bash -c '{cmd}'"])
    return p, term


def ghost_start():
    """(-H) Open terminal with script/transcript recording."""
    term = _find_term()
    if not term:
        return False, "No terminal found! Install a terminal emulator."
    _DATA.mkdir(exist_ok=True)
    if IS_WIN:
        # Windows: PowerShell Start-Transcript
        log_str = str(_LOG)
        cmd = (
            f"Start-Transcript -Path '{log_str}' -Append; "
            "Write-Host '[VURA Ghost Monitor] Recording... Type exit when done.' -ForegroundColor Green; "
            "cmd; "
            "Stop-Transcript"
        )
    else:
        if not shutil.which("script"):
            return False, "'script' not found. Install util-linux."
        sh = os.environ.get("SHELL", "/bin/bash")
        banner = r"echo -e '\033[1;32m[VURA Ghost Monitor]\033[0m Recording... Type exit when done.'"
        if platform.system() == "Darwin":
            cmd = f"{banner}; script -q -a {_LOG} {sh}"
        else:
            cmd = f"{banner}; script -q -a -c {sh} {_LOG}"
    try:
        p, tname = _launch_terminal(cmd, term)
        _ghost["pid"] = p.pid
        return True, f"\u2714 Terminal: {tname} (PID {p.pid})\nRecording \u2192 {_LOG}"
    except Exception as e:
        return False, f"Error launching terminal: {e}"

def ghost_hookall():
    """(-Ha) Read all open terminal sessions."""
    _DATA.mkdir(exist_ok=True)
    terminals = []
    if IS_WIN:
        # Windows: find shell processes via psutil
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
    elif platform.system() == "Darwin":
        dev = Path("/dev")
        for entry in dev.iterdir():
            if entry.name.startswith("ttys") and entry.name[4:].isdigit():
                if os.access(entry, os.R_OK):
                    terminals.append(str(entry))
    else:
        pts_dir = Path("/dev/pts")
        if pts_dir.is_dir():
            for entry in pts_dir.iterdir():
                if entry.name.isdigit():
                    if os.access(entry, os.R_OK): 
                        terminals.append(str(entry))
    if not terminals: 
        return False, "", 0
    if IS_WIN:
        return True, f"Found {len(terminals)} shell(s): {', '.join(terminals)}", len(terminals)
    try:
        out = subprocess.check_output(["who"], text=True, stderr=subprocess.DEVNULL)
        return True, out.strip(), len(terminals)
    except:
        return True, f"Found {len(terminals)} terminals: {', '.join(terminals)}", len(terminals)

def ghost_list_terminals():
    """
    List active *interactive* terminals using psutil.
    Returns list of dicts: {"path": "/dev/ttys000", "name": "ttys000", "shell": "zsh", "pid": 1234}
    Filters out background/daemon terminals — only returns those running an interactive shell.
    """
    INTERACTIVE_SHELLS = {"zsh", "bash", "sh", "fish", "tcsh", "csh", "dash", "ksh"}
    WIN_SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe"}
    results = []
    seen_ttys = set()
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "name", "terminal", "status"]):
            try:
                info = proc.info
                pname = (info.get("name") or "").lower()
                status = info.get("status", "")
                pid = info.get("pid", 0)
                if status in ("zombie", "dead"):
                    continue

                if IS_WIN:
                    # Windows: no tty field — match by process name
                    if pname not in WIN_SHELLS:
                        continue
                    win_id = f"WIN-PID-{pid}"
                    if win_id in seen_ttys:
                        continue
                    seen_ttys.add(win_id)
                    shell_label = pname.replace(".exe", "")
                    results.append({
                        "path": win_id,
                        "name": f"PID-{pid}",
                        "shell": shell_label,
                        "pid": pid,
                    })
                else:
                    # macOS / Linux: filter by tty + interactive shell
                    tty = info.get("terminal")
                    if not tty:
                        continue
                    tty_path = tty if tty.startswith("/dev/") else f"/dev/{tty}"
                    tty_name = Path(tty_path).name
                    if tty_path in seen_ttys:
                        continue
                    if pname not in INTERACTIVE_SHELLS:
                        continue
                    seen_ttys.add(tty_path)
                    results.append({
                        "path": tty_path,
                        "name": tty_name,
                        "shell": pname,
                        "pid": pid,
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except ImportError:
        # Fallback if psutil not installed
        if IS_WIN:
            pass  # No fallback on Windows without psutil
        elif platform.system() == "Darwin":
            dev = Path("/dev")
            for entry in sorted(dev.iterdir()):
                if entry.name.startswith("ttys") and entry.name[4:].isdigit():
                    if os.access(entry, os.R_OK):
                        results.append({"path": str(entry), "name": entry.name, "shell": "?", "pid": 0})
        else:
            pts_dir = Path("/dev/pts")
            if pts_dir.is_dir():
                for entry in sorted(pts_dir.iterdir()):
                    if entry.name.isdigit() and os.access(entry, os.R_OK):
                        results.append({"path": str(entry), "name": entry.name, "shell": "?", "pid": 0})
    except Exception:
        pass
    # Sort by terminal name
    results.sort(key=lambda x: x["name"])
    return results


def ghost_exclude_terminals(pts_list):
    """(-e) Exclude specific terminals from hookall capture."""
    _DATA.mkdir(exist_ok=True)
    exc_file = _DATA / ".vura_exclude_pts"
    try:
        with open(exc_file, "a") as f:
            for pts in pts_list:
                f.write(pts + "\n")
        return True, f"Excluded {len(pts_list)} terminal(s): {', '.join(pts_list)}"
    except Exception as ex:
        return False, f"Error: {ex}"


def ghost_get_excluded():
    """Get list of currently excluded terminals."""
    exc_file = _DATA / ".vura_exclude_pts"
    if not exc_file.exists():
        return []
    try:
        with open(exc_file, "r") as f:
            return [l.strip() for l in f.readlines() if l.strip()]
    except Exception:
        return []

def ghost_stop():
    """Stop recording and return clean data."""
    if _ghost["pid"]:
        try: 
            os.kill(_ghost["pid"], signal.SIGTERM)
        except: 
            pass
        _ghost["pid"] = None
    if not _LOG.exists(): 
        return None
    try:
        with open(_LOG, "r", encoding="utf-8", errors="ignore") as f: 
            raw = f.read()
    except: 
        return None
    clean = _clean_ansi(raw)
    try: 
        _LOG.unlink()
    except: 
        pass
    return clean if len(clean) > 5 else None

def ghost_discard():
    if _ghost["pid"]:
        try: 
            os.kill(_ghost["pid"], signal.SIGTERM)
        except: 
            pass
        _ghost["pid"] = None
    for f in [_LOG, _DATA / ".vura_session_meta.json"]:
        try: 
            f.unlink()
        except: 
            pass

def ghost_active():
    if _ghost["pid"]:
        try: 
            os.kill(_ghost["pid"], 0); 
            return True
        except: 
            _ghost["pid"] = None
    return _LOG.exists()

def ghost_size():
    if _LOG.exists():
        s = _LOG.stat().st_size
        return f"{s/1024:.1f}KB" if s > 1024 else f"{s}B"
    return "0"

# ═══════════════════════════════════════════════════════════════
# UI HELPERS
# ═══════════════════════════════════════════════════════════════
def run_bg(page, fn, cb=None):
    def w():
        try:
            r = fn()
            if cb: cb(r)
        except Exception as e:
            if cb: cb(f"ERROR: {e}\n{traceback.format_exc()}")
        finally:
            try: page.update()
            except: pass
    threading.Thread(target=w, daemon=True).start()

def card(content, title=None, w=None):
    ch = []
    if title:
        ch.append(ft.Text(title, size=14, weight=ft.FontWeight.BOLD, color=C.T))
        ch.append(ft.Divider(height=1, color=C.N3))
    ch.extend(content if isinstance(content, list) else [content])
    return ft.Container(content=ft.Column(ch, spacing=10), bgcolor=C.N2,
        border_radius=12, padding=20, width=w, border=ft.Border.all(1, C.N3))

def sec(text, icon=None):
    r = []
    if icon: r.append(ft.Icon(icon, color=C.T, size=20))
    r.append(ft.Text(text, size=18, weight=ft.FontWeight.BOLD, color=C.W))
    return ft.Row(r, spacing=8)

def btn(label, icon=None, click=None, color=None, w=None):
    color = color or C.T
    r = []
    if icon: r.append(ft.Icon(icon, color=C.W, size=18))
    r.append(ft.Text(label, size=13, color=C.W, weight=ft.FontWeight.W_600))
    return ft.Container(content=ft.Row(r, spacing=8, alignment=ft.MainAxisAlignment.CENTER),
        bgcolor=color, border_radius=8, padding=ft.Padding.symmetric(horizontal=16, vertical=10),
        width=w, height=42, on_click=click)

def dd(label, opts, val, w=180):
    return ft.Dropdown(label=label, width=w,
        options=[ft.dropdown.Option(*o) if isinstance(o, tuple) else ft.dropdown.Option(o) for o in opts],
        value=val, border_color=C.N3, focused_border_color=C.T, color=C.W,
        label_style=ft.TextStyle(color=C.DM), bgcolor=C.N)

def tf(label, val="", w=None, ml=False, pw=False, icon=None, ro=False, lines=6):
    kw = dict(label=label, value=val, border_color=C.N3, focused_border_color=C.T,
              color=C.W, label_style=ft.TextStyle(color=C.DM), bgcolor=C.N)
    if w: kw["width"] = w
    if ml: kw["multiline"] = True; kw["min_lines"] = lines; kw["max_lines"] = 100
    if pw: kw["password"] = True; kw["can_reveal_password"] = True
    if icon: kw["prefix_icon"] = icon
    if ro: kw["read_only"] = True
    return ft.TextField(**kw)


# ═══════════════════════════════════════════════════════════════
# MAIN APP
# ═══════════════════════════════════════════════════════════════
def main(page: ft.Page):
    page.title = "VURA — Vulnerability Reporting AI"
    page.bgcolor = C.BG; page.padding = 0
    page.window.width = 1200; page.window.height = 800
    page.window.min_width = 900; page.window.min_height = 600
    page.theme_mode = ft.ThemeMode.DARK

    lang = {"v": "e"}  # "e" or "a"
    def t(k):
        e = L.get(k, {})
        return e.get(lang["v"], e.get("e", k))

    ghost_data = {"raw": None}  # Shared between Monitor and Analyze

    # ── Notification bar ──
    nbar = ft.Container(content=ft.Text("", size=13, color=C.W), bgcolor=C.T,
        height=0, padding=ft.Padding.symmetric(horizontal=20, vertical=0),
        animate=ft.Animation(300, ft.AnimationCurve.EASE_OUT))
    def snack(msg, color=None):
        nbar.content = ft.Text(msg, size=13, color=C.W)
        nbar.bgcolor = color or C.T; nbar.height = 42
        nbar.padding = ft.Padding.symmetric(horizontal=20, vertical=10)
        page.update()
        def h():
            import time; time.sleep(3)
            nbar.height = 0; nbar.padding = ft.Padding.symmetric(horizontal=20, vertical=0)
            try: page.update()
            except: pass
        threading.Thread(target=h, daemon=True).start()

    # ══════════════════ HOME ══════════════════
    def build_home():
        items = []
        # Open Source - No license status needed
        items.append(ft.Row([ft.Icon(ft.Icons.VERIFIED_USER, color=C.G, size=18),
            ft.Text("License:", color=C.DM, size=13),
            ft.Text("Free & Open Source", color=C.G, size=13, weight=ft.FontWeight.BOLD)], spacing=6))
        
        try:
            from app.utils.config import get_config_summary, validate_config
            sm = get_config_summary(); er = validate_config(); ok = not er; cl = C.G if ok else C.R
            al = f"{sm['provider']}/{sm['model_name']}" if ok else t("nocfg")
            items.append(ft.Row([ft.Icon(ft.Icons.SMART_TOY, color=cl, size=18),
                ft.Text(t("ai"), color=C.DM, size=13),
                ft.Text(al, color=cl, size=13, weight=ft.FontWeight.BOLD)], spacing=6))
        except: items.append(ft.Text(f"{t('ai')} {t('uchk')}", color=C.O, size=13))

        rc = 0
        try:
            for ext in ["md","json","pdf","docx"]:
                rc += len(glob.glob(str(_ROOT / "reports" / ext / f"*.{ext}")))
        except: pass
        sa = ghost_active(); sl = t("rec") if sa else t("nosess")

        return ft.Column([
            ft.Container(content=ft.Column([
                ft.Text("VURA", size=52, weight=ft.FontWeight.BOLD, color=C.T),
                ft.Text(t("sub"), size=16, color=C.DM, italic=True),
                ft.Text(f"v{VER}", size=12, color=C.DM)],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=2),
                alignment=ft.Alignment(0, 0), padding=ft.Padding.only(top=30, bottom=10)),
            ft.Row([
                card([ft.Row([ft.Icon(ft.Icons.DESCRIPTION, color=C.T, size=28),
                    ft.Column([ft.Text(str(rc), size=28, weight=ft.FontWeight.BOLD, color=C.W),
                    ft.Text(t("reps"), size=12, color=C.DM)], spacing=0)], spacing=12)], w=200),
                card([ft.Row([ft.Icon(ft.Icons.FIBER_MANUAL_RECORD, color=C.G if sa else C.DM, size=28),
                    ft.Column([ft.Text(t("actv") if sa else t("idle"), size=20, weight=ft.FontWeight.BOLD,
                        color=C.G if sa else C.DM),
                    ft.Text(sl, size=12, color=C.DM)], spacing=0)], spacing=12)], w=280),
            ], spacing=16, alignment=ft.MainAxisAlignment.CENTER),
            ft.Container(height=10), card(items, title=t("syst")), ft.Container(height=10),
            sec(t("qact"), ft.Icons.FLASH_ON),
            ft.Row([
                btn(t("monitor"), ft.Icons.RADIO_BUTTON_CHECKED, lambda _: nav(1), C.T, 180),
                btn(t("analyze"), ft.Icons.ANALYTICS, lambda _: nav(2), C.T2, 180),
                btn(t("recon"), ft.Icons.RADAR, lambda _: nav(3), C.CD, 180),
                btn(t("reports"), ft.Icons.FOLDER_OPEN, lambda _: nav(4), C.S2, 180),
            ], spacing=12, alignment=ft.MainAxisAlignment.CENTER, wrap=True),
        ], scroll=ft.ScrollMode.AUTO, spacing=12, horizontal_alignment=ft.CrossAxisAlignment.CENTER)

    # ══════════════════ GHOST MONITOR — ALL COMMANDS ══════════════════
    def build_monitor():
        out = ft.Text("", size=12, color=C.DM, selectable=True)
        ss = ft.Text("...", size=14, color=C.DM)
        si = ft.Icon(ft.Icons.FIBER_MANUAL_RECORD, color=C.DM, size=16)
        silent_cb = ft.Checkbox(label=t("silent_mode"), value=False)

        def ref():
            if ghost_active():
                ss.value = f"{t('rec')} ({ghost_size()})"; ss.color = si.color = C.G
            else:
                ss.value = t("nosess"); ss.color = si.color = C.DM
            page.update()

        def on_start(e):  # -H
            ok, msg = ghost_start()
            out.value = msg; out.color = C.G if ok else C.R
            if ok: snack(t("rec"), C.G)
            ref(); page.update()

        def on_hookall(e):  # -Ha
            out.value = t("hookall_reading"); out.color = C.Y; page.update()
            def do():
                return ghost_hookall()
            def done(r):
                ok, msg, cnt = r
                if ok and cnt > 0:
                    ghost_data["raw"] = msg  # Store hookall data for Stop & Report
                    out.value = t("hookall_done").format(n=len(msg), t=cnt) + f"\n\n{msg}"
                    out.color = C.G; snack(t("hookall_done").format(n=len(msg), t=cnt), C.G)
                else:
                    out.value = t("hookall_none"); out.color = C.O
            run_bg(page, do, done)

        def on_exclude(e):  # -e  → interactive terminal selector dialog
            terms = ghost_list_terminals()  # list of dicts with path/name/shell/pid
            excluded = ghost_get_excluded()
            if not terms:
                out.value = "No interactive terminals found. Only shells like zsh/bash are shown."
                out.color = C.O; page.update()
                return

            # Build checkbox list for each terminal
            cb_map = {}  # path -> checkbox
            cb_col = ft.Column(spacing=4, scroll=ft.ScrollMode.AUTO, height=300)
            for ti in terms:
                tpath = ti["path"]
                tname = ti["name"]
                shell = ti["shell"]
                pid   = ti["pid"]
                already = tpath in excluded
                # Pretty label: "Terminal: ttys000 (zsh)"
                label_text = f"  {tname}  ({shell})"
                cb = ft.Checkbox(
                    label="",  # we use custom content instead
                    value=already,
                    disabled=already,
                )
                # Build a rich row: [checkbox] [icon] Terminal: ttys000 (zsh)  [PID badge]
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
            count_txt = ft.Text(
                f"{len(terms)} interactive terminal(s) detected",
                size=11, color=C.DM, italic=True,
            )

            def do_exclude(ev):
                selected = [p for p, c in cb_map.items() if c.value and p not in excluded]
                if not selected:
                    result_txt.value = "No new terminals selected."
                    result_txt.color = C.O
                    page.update()
                    return
                ok, msg = ghost_exclude_terminals(selected)
                if ok:
                    result_txt.value = f"✔ {msg}"
                    result_txt.color = C.G
                    out.value = f"✔ {msg}"; out.color = C.G
                    snack(t("excluded"), C.G)
                    for p in selected:
                        cb_map[p].disabled = True
                else:
                    result_txt.value = f"✘ {msg}"
                    result_txt.color = C.R
                page.update()

            def close_dlg(ev):
                dlg.open = False
                page.update()

            dlg = ft.AlertDialog(
                modal=True,
                title=ft.Row([
                    ft.Icon(ft.Icons.DEVICES, color=C.T, size=22),
                    ft.Text("Active Terminals", size=18, weight=ft.FontWeight.BOLD, color=C.T),
                ], spacing=8),
                content=ft.Container(
                    content=ft.Column([
                        ft.Text(
                            "Select interactive terminals to exclude from HookAll:",
                            size=13, color=C.DM,
                        ),
                        count_txt,
                        ft.Container(height=6),
                        cb_col,
                        ft.Container(height=8),
                        result_txt,
                    ], tight=True),
                    width=480, height=420,
                ),
                actions=[
                    ft.TextButton("Cancel", on_click=close_dlg),
                    ft.Button(
                        "Exclude Selected",
                        icon=ft.Icons.BLOCK,
                        bgcolor=C.T, color=C.W,
                        on_click=do_exclude,
                    ),
                ],
                actions_alignment=ft.MainAxisAlignment.END,
                bgcolor=C.N2,
                shape=ft.RoundedRectangleBorder(radius=12),
            )
            page.overlay.append(dlg)
            dlg.open = True
            page.update()

        def on_stop_collect(e):  # Stop & Collect (data for Analyze)
            out.value = t("stop_msg"); out.color = C.Y; page.update()
            def do(): return ghost_stop()
            def done(r):
                if r:
                    n = len(r)
                    out.value = t("capt").format(n=f"{n:,}"); out.color = C.G
                    ghost_data["raw"] = r; snack(f"{n:,} chars", C.G)
                else:
                    out.value = t("nosf"); out.color = C.O
                ref()
            run_bg(page, do, done)

        def on_stop_report(e):  # -R (Stop + Generate Report directly)
            out.value = t("stop_msg"); out.color = C.Y; page.update()
            def do():
                # Try ghost_stop() first, fall back to ghost_data["raw"]
                raw = ghost_stop()
                if not raw:
                    raw = ghost_data.get("raw")
                if not raw:
                    # Check if log file has data
                    if _LOG.exists():
                        try:
                            with open(_LOG, "r", encoding="utf-8", errors="ignore") as f:
                                raw = _clean_ansi(f.read())
                        except Exception:
                            pass
                if not raw or len(raw.strip()) < 5:
                    return "WARN: No data collected yet. Please start recording or hook a terminal first."
                # Store for reuse
                ghost_data["raw"] = raw
                try:
                    from app.core.ai_engine import generate_report
                    from app.utils.formatter import save_markdown_report, add_compliance_section
                    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    sid = f"VURA_Ghost_{ts}"
                    prep = f"Tool: Ghost Monitor\nContext: Live terminal\n\nOutput:\n{raw}"
                    ct = generate_report(prep, language="English", output_format="md",
                        approach="defense", include_script=False, scan_type="terminal", report_context="")
                    if not ct: return "ERROR: AI returned empty response"
                    ct = add_compliance_section(ct)
                    sv, _, _ = save_markdown_report(ct, sid, "defense")
                    return f"OK: {t('rsaved')} {sv}\n\n{ct[:1500]}" if sv else f"OK:\n{ct[:1500]}"
                except Exception as ex: return f"ERROR: {ex}"
            def done(r):
                msg = str(r)
                if msg.startswith("WARN:"):
                    out.value = msg[5:].strip(); out.color = C.O
                    snack(msg[5:].strip(), C.O)
                elif msg.startswith("ERROR:"):
                    out.value = msg; out.color = C.R
                else:
                    out.value = msg[3:].strip() if msg.startswith("OK:") else msg
                    out.color = C.G; snack(t("rok"), C.G)
                ref()
            run_bg(page, do, done)

        def on_discard(e):
            ghost_discard(); ghost_data["raw"] = None
            out.value = t("disc"); out.color = C.Y; snack(t("disc"), C.O)
            ref(); page.update()

        ref()
        return ft.Column([
            sec(t("ghost"), ft.Icons.RADIO_BUTTON_CHECKED), ft.Container(height=8),
            card([ft.Row([si, ss], spacing=8)], title=t("sesst")),
            ft.Container(height=10),
            ft.Row([
                btn(t("start_ghost"), ft.Icons.PLAY_ARROW, on_start, C.T, 200),
                btn(t("start_hookall"), ft.Icons.ALL_INCLUSIVE, on_hookall, C.CD, 200),
                btn(t("exclude"), ft.Icons.BLOCK, on_exclude, C.S2, 200),
            ], spacing=10, wrap=True),
            ft.Row([
                btn(t("stop_collect"), ft.Icons.STOP_CIRCLE, on_stop_collect, C.O, 200),
                btn(t("stop_report"), ft.Icons.SUMMARIZE, on_stop_report, C.T2, 220),
                btn(t("discard"), ft.Icons.DELETE, on_discard, C.R, 140),
            ], spacing=10, wrap=True),
            silent_cb,
            ft.Container(height=10), card([out], title=t("out")),
            ft.Container(height=10),
            card([ft.Text(t("how_txt"), size=12, color=C.DM)], title=t("how")),
        ], scroll=ft.ScrollMode.AUTO, spacing=8)

    # ══════════════════ ANALYZE — ALL INPUT MODES ══════════════════
    def build_analyze():
        out = ft.Text("", size=12, color=C.DM, selectable=True)
        pr = ft.ProgressRing(width=24, height=24, color=C.T, visible=False)
        tab_i = [0]
        tabs_r = ft.Row(spacing=0)
        tab_lbl = [t("man"), t("file"), t("gdata"), t("hist")]

        def mktabs():
            tabs_r.controls.clear()
            for i, lb in enumerate(tab_lbl):
                s = i == tab_i[0]
                tabs_r.controls.append(ft.Container(
                    content=ft.Text(lb, size=13, color=C.T if s else C.DM,
                        weight=ft.FontWeight.BOLD if s else ft.FontWeight.NORMAL),
                    border=ft.Border.only(bottom=ft.BorderSide(2, C.T) if s else ft.BorderSide(1, C.N3)),
                    padding=ft.Padding.symmetric(horizontal=16, vertical=10),
                    on_click=lambda e, idx=i: st(idx)))
        def st(i): tab_i[0] = i; mktabs(); page.update()
        mktabs()

        mi = tf(t("paste"), ml=True, lines=6)
        fi = tf(t("fpath"), icon=ft.Icons.ATTACH_FILE, w=500)
        hl = tf(t("hlines"), val="50", w=100)
        nk = "a" if lang["v"] == "a" else "n"
        rtd = dd(t("rtype"), [(k, f"{v['i']} {v.get(nk,v['n'])}") for k,v in RTYPES.items()], "1", 280)
        cdd = tf(t("cdesc")); cdd.visible = False
        def otc(e): cdd.visible = (rtd.value == "5"); page.update()
        rtd.on_change = otc
        fmd = dd(t("fmt"), [("md","Markdown"),("pdf","PDF"),("docx","DOCX"),("json","JSON")], "md", 140)
        lnd = dd(t("lang"), LANGS, "Arabic" if lang["v"]=="a" else "English", 180)
        apd = dd(t("appr"), [("defense",t("defense")),("offense",t("offense"))], "defense", 160)
        std = dd(t("stype"), [("terminal","Terminal"),("recon","Recon"),("executive","Executive"),("dual","Dual")], "terminal", 160)
        ntd = dd(t("notify"), [("","None"),("short","Short"),("long","Long")], "", 140)

        def on_gen(e):
            idx = tab_i[0]; raw = None
            if idx == 0: raw = mi.value
            elif idx == 1:
                fp = fi.value.strip() if fi.value else ""
                if fp and Path(fp).exists():
                    try:
                        with open(fp, "r", encoding="utf-8", errors="ignore") as f: raw = f.read()
                    except Exception as ex: out.value = f"Error: {ex}"; out.color = C.R; page.update(); return
                else: snack(t("fpath"), C.R); return
            elif idx == 2:
                raw = ghost_data.get("raw")
                if not raw: snack(t("nogd"), C.O); return
            elif idx == 3:
                try:
                    from app.cli import read_terminal_history
                    raw = read_terminal_history(int(hl.value or "50"))
                except Exception as ex: out.value = f"Error: {ex}"; out.color = C.R; page.update(); return
            if not raw or len(raw.strip()) < 5: snack(t("nodata"), C.O); return

            rk = rtd.value or "1"; rt = RTYPES[rk]; rc = rt["c"]
            if rk == "5": rc = cdd.value.strip() or "General"
            of = fmd.value or "md"; la = lnd.value or "English"
            ap = apd.value or "defense"; sty = std.value or "terminal"
            nt = ntd.value or None
            pr.visible = True; out.value = t("gening"); out.color = C.Y; page.update()

            def _g():
                try:
                    from app.core.ai_engine import generate_report
                    from app.utils.formatter import (save_markdown_report, export_to_pdf,
                        export_to_docx, save_json_report, add_compliance_section, generate_dual_reports)

                    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S"); sid = f"VURA_GUI_{ts}"
                    prep = f"Tool: GUI\nContext: {rt['n']}\n\nOutput:\n{raw}"

                    if sty == "dual":
                        res = generate_dual_reports(raw_data=prep, session_id=sid, approach=ap,
                            language=la, output_format=of, include_script=False, notify=nt)
                        if res and res.get("technical", {}).get("content"):
                            return f"✔ Dual!\nTech: {res['technical'].get('file','')}\nExec: {res['executive'].get('file','')}"
                        return "ERROR: Dual failed"

                    ct = generate_report(prep, language=la, output_format=of, approach=ap,
                        include_script=False, scan_type=sty, report_context=rc)
                    if not ct: return "ERROR: AI empty"
                    if any(ct.startswith(m) for m in ["# Connection Error","# VURA Error","# Error\n"]):
                        return f"ERROR:\n{ct[:500]}"
                    if of != "json" and sty != "executive": ct = add_compliance_section(ct)

                    sv = None
                    if of == "json": sv = save_json_report(ct, sid)
                    elif of == "pdf":
                        _, _, en = save_markdown_report(ct, sid, ap); sv = export_to_pdf(en, sid)
                    elif of == "docx":
                        _, _, en = save_markdown_report(ct, sid, ap); sv = export_to_docx(en, sid)
                    else: sv, _, _ = save_markdown_report(ct, sid, ap)

                    # Telegram notification
                    if nt:
                        try:
                            from app.utils.notifier import send_telegram_alert, send_telegram_file
                            send_telegram_alert(sv, ct, mode=nt)
                            if of == "pdf" and sv: send_telegram_file(sv, f"VURA Report — {sid}")
                        except: pass

                    return f"✔ {t('rsaved')} {sv}\n\n{ct[:2000]}" if sv else f"✔\n{ct[:2000]}"
                except Exception as ex: return f"ERROR: {ex}\n{traceback.format_exc()}"

            def _d(r):
                pr.visible = False
                if str(r).startswith("ERROR"):
                    out.value = str(r); out.color = C.R; snack(t("rfail"), C.R)
                else:
                    out.value = str(r); out.color = C.G; snack(t("rok"), C.G)
            run_bg(page, _g, _d)

        return ft.Column([
            sec(t("anly"), ft.Icons.ANALYTICS), ft.Container(height=6),
            tabs_r, ft.Container(height=6), mi, fi,
            ft.Row([ft.Text(t("hlines")+":", color=C.DM, size=13), hl], spacing=8),
            ft.Divider(color=C.N3),
            ft.Row([rtd, fmd, lnd], spacing=10, wrap=True), cdd,
            ft.Row([apd, std, ntd], spacing=10, wrap=True),
            ft.Container(height=8),
            ft.Row([btn(t("gen"), ft.Icons.AUTO_AWESOME, on_gen, C.T, 220), pr], spacing=12),
            ft.Container(height=10), card([out], title=t("out")),
        ], scroll=ft.ScrollMode.AUTO, spacing=8)

    # ══════════════════ RECON (-r) ══════════════════
    def build_recon():
        out = ft.Text("", size=12, color=C.DM, selectable=True)
        rp = ft.ProgressRing(width=24, height=24, color=C.T, visible=False)
        di = tf(t("tdom"), icon=ft.Icons.LANGUAGE, w=400)
        rl = dd(t("lang"), LANGS, "Arabic" if lang["v"]=="a" else "English", 160)
        rf = dd(t("fmt"), [("md","Markdown"),("pdf","PDF"),("docx","DOCX"),("json","JSON")], "md", 140)
        sa=ft.Checkbox(label="Amass"); sh=ft.Checkbox(label="theHarvester")
        ss=ft.Checkbox(label="Shodan"); sn=ft.Checkbox(label="Nmap"); sw=ft.Checkbox(label="Whois")
        tst = ft.Text("...", size=12, color=C.DM)
        def ck():
            try:
                from app.core.recon import check_all_tools
                tools = check_all_tools()
                tst.value = "  |  ".join([f"{'✔' if v else '✘'} {k}" for k,v in tools.items()])
            except: tst.value = t("uchk")
            page.update()
        threading.Thread(target=ck, daemon=True).start()

        def on_run(e):
            d = di.value.strip()
            if not d: snack(t("edom"), C.O); return
            rp.visible = True; out.value = t("rrunning"); out.color = C.Y; page.update()
            def do():
                try:
                    from app.core.recon import run_full_recon
                    from app.core.ai_engine import generate_report
                    from app.utils.formatter import (save_markdown_report, export_to_pdf, export_to_docx,
                        save_json_report, add_compliance_section)
                    agg = run_full_recon(d, skip_amass=sa.value, skip_theharvester=sh.value,
                        skip_shodan=ss.value, skip_nmap=sn.value, skip_whois=sw.value)
                    if not agg or len(agg.strip()) < 20: return "ERROR: No data"
                    la = rl.value or "English"; fm = rf.value or "md"
                    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S"); sid = f"VURA_Recon_{ts}"
                    ct = generate_report(f"Tool: Recon\nContext: {d}\n\n{agg}", language=la,
                        output_format=fm, approach="defense", include_script=False,
                        scan_type="recon", report_context="Recon/OSINT")
                    if not ct: return "ERROR: AI empty"
                    if fm != "json": ct = add_compliance_section(ct)
                    sv = None
                    if fm == "json": sv = save_json_report(ct, sid)
                    elif fm == "pdf": _, _, en = save_markdown_report(ct, sid, "defense"); sv = export_to_pdf(en, sid)
                    elif fm == "docx": _, _, en = save_markdown_report(ct, sid, "defense"); sv = export_to_docx(en, sid)
                    else: sv, _, _ = save_markdown_report(ct, sid, "defense")
                    return f"✔ {t('rsaved')} {sv}\n\n{agg[:400]}\n\n{ct[:400]}" if sv else f"✔\n{ct[:1200]}"
                except Exception as ex: return f"ERROR: {ex}\n{traceback.format_exc()}"
            def done(r):
                rp.visible = False
                if str(r).startswith("ERROR"): out.value = str(r); out.color = C.R
                else: out.value = str(r); out.color = C.G; snack(t("rdone"), C.G)
            run_bg(page, do, done)

        return ft.Column([sec(t("rtitle"), ft.Icons.RADAR), ft.Container(height=8),
            card([tst], title=t("tstat")), ft.Container(height=8),
            di, ft.Row([rl, rf], spacing=10), ft.Container(height=4),
            card([ft.Text(t("skip"), size=13, color=C.DM),
                ft.Row([sw, sa, sh, ss, sn], spacing=8, wrap=True)]),
            ft.Container(height=8),
            ft.Row([btn(t("rrun"), ft.Icons.PLAY_ARROW, on_run, C.T, 220), rp], spacing=12),
            ft.Container(height=10), card([out], title=t("rout")),
        ], scroll=ft.ScrollMode.AUTO, spacing=8)

    # ══════════════════ REPORTS (-Hy, -Rc) ══════════════════
    def build_reports():
        asess = {}
        scol = ft.Column(spacing=4, scroll=ft.ScrollMode.AUTO, expand=True)
        vtitle = ft.Text(t("selrep"), size=15, color=C.DM, weight=ft.FontWeight.BOLD)
        vcont = tf("", ro=True, ml=True, lines=25); vcont.expand = True
        ftabs = ft.Row(spacing=6)

        def load():
            asess.clear(); scol.controls.clear()
            rr = _ROOT / "reports"; files = []
            for ext in ["md","json","pdf","docx","sh"]:
                files.extend(glob.glob(str(rr / ext / f"*.{ext}")))
            if not files: scol.controls.append(ft.Text(t("norep"), color=C.DM, size=13)); return
            for p in files:
                nm = Path(p).stem
                ex = Path(p).suffix[1:].upper()
                if nm not in asess: asess[nm] = {"f": [], "p": {}}
                if ex not in asess[nm]["f"]: asess[nm]["f"].append(ex); asess[nm]["p"][ex] = p
            scol.controls.append(ft.Text(t("sf").format(s=len(asess), f=len(files)), size=12, color=C.DM))
            for sid in sorted(asess.keys(), reverse=True):
                d = asess[sid]
                badges = ft.Row([ft.Container(
                    content=ft.Text(f, size=9, color=C.W, weight=ft.FontWeight.W_600),
                    bgcolor={"MD":C.T,"PDF":C.R,"DOCX":C.CD,"JSON":C.O,"SH":C.S2}.get(f, C.N3),
                    border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=1),
                ) for f in d["f"]], spacing=3)
                dp = ""
                try:
                    pts = sid.split("_")
                    if len(pts) >= 3: x = pts[-2]; dp = f"{x[:4]}-{x[4:6]}-{x[6:8]}"
                except: pass
                def mk(s):
                    def c(e): sel(s)
                    return c
                scol.controls.append(ft.Container(content=ft.Column([
                    ft.Row([ft.Icon(ft.Icons.DESCRIPTION, color=C.T, size=14),
                        ft.Text(sid, size=11, color=C.W, expand=True, max_lines=1,
                            overflow=ft.TextOverflow.ELLIPSIS)], spacing=6),
                    ft.Row([ft.Text(dp, size=10, color=C.DM) if dp else ft.Container(), badges],
                        spacing=6, alignment=ft.MainAxisAlignment.SPACE_BETWEEN)], spacing=4),
                    bgcolor=C.N, border_radius=8, padding=ft.Padding.symmetric(horizontal=10, vertical=8),
                    on_click=mk(sid)))

        def sel(sid):
            d = asess.get(sid, {}); fmts = d.get("f", []); paths = d.get("p", {})
            ftabs.controls.clear()
            for f in fmts:
                def mkf(ff, pp):
                    def c(e): ldc(sid, ff, pp)
                    return c
                fc = {"MD":C.T,"PDF":C.R,"DOCX":C.CD,"JSON":C.O,"SH":C.S2}.get(f, C.N3)
                ftabs.controls.append(ft.Container(
                    content=ft.Text(f, size=12, color=C.W, weight=ft.FontWeight.W_600),
                    bgcolor=fc, border_radius=6, padding=ft.Padding.symmetric(horizontal=14, vertical=6),
                    on_click=mkf(f, paths.get(f, ""))))
            for pf in ["MD","JSON","SH"]:
                if pf in fmts: ldc(sid, pf, paths[pf]); return
            vtitle.value = f"📄 {sid}"; vcont.value = t("bin"); page.update()

        def ldc(sid, fmt, fp):
            vtitle.value = f"📄 {sid} [{fmt}]"
            if not Path(fp).exists(): vcont.value = f"Not found: {fp}"; page.update(); return
            if fmt in ("PDF","DOCX"): vcont.value = f"{t('bin')}\n📁 {fp}"; page.update(); return
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as f: vcont.value = f.read()
            except Exception as ex: vcont.value = f"Error: {ex}"
            page.update()

        def on_ref(e):
            load(); vtitle.value = t("selrep"); vcont.value = ""; ftabs.controls.clear()
            snack(t("ref"), C.T); page.update()

        def on_opf(e):
            rr = str(_ROOT / "reports")
            try:
                if platform.system()=="Darwin": subprocess.Popen(["open", rr])
                elif platform.system()=="Linux": subprocess.Popen(["xdg-open", rr])
                else: subprocess.Popen(["explorer", rr])
            except: snack(f"Open: {rr}", C.O)

        def on_recreate(e):  # -Rc
            state_file = _DATA / ".vura_state.json"
            if not state_file.exists():
                snack(t("recreate_no"), C.O); return
            out_txt = ft.Text(t("recreating"), size=12, color=C.Y)
            snack(t("recreating"), C.Y)
            def do():
                try:
                    with open(state_file, "r") as f: state = json.load(f)
                    from app.cli import process_and_report
                    process_and_report(
                        state["raw_data"], state.get("tool"), state.get("context"),
                        state.get("format","md"), state.get("language","English"),
                        state.get("notify"), state.get("approach","defense"))
                    return "OK"
                except Exception as ex: return f"ERROR: {ex}"
            def done(r):
                if r == "OK": snack(t("recreate_ok"), C.G); load(); page.update()
                else: snack(str(r), C.R)
            run_bg(page, do, done)

        load()
        left = ft.Container(content=ft.Column([
            ft.Text(t("rlist"), size=14, weight=ft.FontWeight.BOLD, color=C.T),
            ft.Divider(height=1, color=C.N3), scol], spacing=6, expand=True),
            bgcolor=C.N2, border_radius=12, padding=12, width=340,
            border=ft.Border.all(1, C.N3), expand=True)
        right = ft.Container(content=ft.Column([vtitle, ftabs,
            ft.Divider(height=1, color=C.N3), vcont], spacing=8, expand=True,
            scroll=ft.ScrollMode.AUTO),
            bgcolor=C.N2, border_radius=12, padding=16,
            border=ft.Border.all(1, C.N3), expand=2)

        return ft.Column([sec(t("arch"), ft.Icons.FOLDER_OPEN),
            ft.Row([btn(t("ref"), ft.Icons.REFRESH, on_ref, C.T, 130),
                    btn(t("opf"), ft.Icons.FOLDER, on_opf, C.CD, 150),
                    btn(t("recreate"), ft.Icons.REPLAY, on_recreate, C.O, 220)], spacing=10, wrap=True),
            ft.Container(height=6), ft.Row([left, right], spacing=12, expand=True),
        ], spacing=8, expand=True)

    # ══════════════════ SETTINGS (-Ch) ══════════════════
    def build_settings():
        cfg = {}
        try:
            from app.utils.config import load_api_config; cfg = load_api_config() or {}
        except: pass
        pd = dd(t("prov"), ["openai","openrouter","anthropic","deepseek","qwen","gemini",
            "groq","mistral","together","venice","github","custom"], cfg.get("provider",""), 250)
        ak = tf(t("akey"), cfg.get("api_key",""), 400, pw=True)
        mn = tf(t("mname"), cfg.get("model_name",""), 300)
        bu = tf(t("curl"), cfg.get("base_url",""), 400)
        tt = tf(t("tgt"), cfg.get("tg_bot_token",""), 400, pw=True)
        tc = tf(t("tgc"), cfg.get("tg_chat_id",""), 200)
        sk = tf(t("shk"), cfg.get("shodan_api_key",""), 400, pw=True)
        svs = ft.Text("", size=13)

        def on_lang(e):
            lang["v"] = "a" if lang["v"] == "e" else "e"
            pcache.clear(); rbnav(); nav(5)

        ltg = ft.Container(content=ft.Row([ft.Icon(ft.Icons.TRANSLATE, color=C.W, size=18),
            ft.Text("العربية" if lang["v"]=="e" else "English", size=14, color=C.W, weight=ft.FontWeight.BOLD)],
            spacing=8, alignment=ft.MainAxisAlignment.CENTER),
            bgcolor=C.T2, border_radius=8, padding=ft.Padding.symmetric(horizontal=16, vertical=10),
            width=180, height=46, on_click=on_lang)

        def on_save(e):
            try:
                from app.utils.config import save_api_config
                save_api_config({
                    "provider": pd.value or "", "api_key": ak.value or "",
                    "model_name": mn.value or "", "base_url": bu.value or "",
                    "tg_bot_token": tt.value or "", "tg_chat_id": tc.value or "",
                    "shodan_api_key": sk.value or "",
                    "gophish_api_key": cfg.get("gophish_api_key",""),
                    "gophish_url": cfg.get("gophish_url","https://localhost:3333")})
                svs.value = f"✔ {t('saved')}"; svs.color = C.G; snack(t("saved"), C.G)
            except Exception as ex: svs.value = f"Error: {ex}"; svs.color = C.R
            page.update()

        return ft.Column([sec(t("stitle"), ft.Icons.SETTINGS), ft.Container(height=6),
            card([ft.Text(t("uilang"), size=15, weight=ft.FontWeight.BOLD, color=C.T),
                ft.Container(height=6),
                ft.Row([ltg, ft.Text("EN ↔ AR", size=13, color=C.DM)], spacing=12)], title=t("uilang")),
            ft.Container(height=8), card([pd, ak, mn, bu], title=t("ai")),
            ft.Container(height=8), card([tt, tc], title=t("tgn")),
            ft.Container(height=8), card([sk], title=t("integ")),
            ft.Container(height=12),
            ft.Row([btn(t("save"), ft.Icons.SAVE, on_save, C.T, 220), svs], spacing=12),
        ], scroll=ft.ScrollMode.AUTO, spacing=8)

    
    # ══════════════════ NAV ══════════════════
    pcache = {}
    def gp(i):
        if i not in pcache:
            bld = [build_home, build_monitor, build_analyze, build_recon,
                   build_reports, build_settings]
            pcache[i] = bld[i]()
        return pcache[i]

    ca = ft.Container(content=gp(0), expand=True, padding=24)
    nr = ft.NavigationRail(selected_index=0, label_type=ft.NavigationRailLabelType.ALL,
        min_width=80, min_extended_width=200, bgcolor=C.N, indicator_color=C.T,
        on_change=lambda e: nav(e.control.selected_index),
        destinations=[
            ft.NavigationRailDestination(icon=ft.Icons.HOME_OUTLINED, selected_icon=ft.Icons.HOME, label=t("home")),
            ft.NavigationRailDestination(icon=ft.Icons.RADIO_BUTTON_UNCHECKED, selected_icon=ft.Icons.RADIO_BUTTON_CHECKED, label=t("monitor")),
            ft.NavigationRailDestination(icon=ft.Icons.ANALYTICS_OUTLINED, selected_icon=ft.Icons.ANALYTICS, label=t("analyze")),
            ft.NavigationRailDestination(icon=ft.Icons.RADAR_OUTLINED, selected_icon=ft.Icons.RADAR, label=t("recon")),
            ft.NavigationRailDestination(icon=ft.Icons.FOLDER_OUTLINED, selected_icon=ft.Icons.FOLDER, label=t("reports")),
            ft.NavigationRailDestination(icon=ft.Icons.SETTINGS_OUTLINED, selected_icon=ft.Icons.SETTINGS, label=t("settings")),
        ])

    def rbnav():
        lbl = [t("home"), t("monitor"), t("analyze"), t("recon"), t("reports"), t("settings")]
        for i, d in enumerate(nr.destinations): d.label = lbl[i]

    def nav(i):
        if i in (0, 1, 4): pcache.pop(i, None)
        ca.content = gp(i); nr.selected_index = i; page.update()

    page.add(ft.Column([
        ft.Row([nr, ft.VerticalDivider(width=1, color=C.N3), ca], expand=True, spacing=0),
        nbar,
    ], expand=True, spacing=0))

if __name__ == "__main__":
    ft.run(main)
