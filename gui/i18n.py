"""
VURA GUI — Internationalization
═══════════════════════════════════
Translation engine supporting EN/AR with extensible language support.
"""

from typing import Optional


# ══════════════════════════════════════════════════════════════════════
# Translation Strings
# ══════════════════════════════════════════════════════════════════════

L = {
    "home": {"e": "Home", "a": "الرئيسية"},
    "monitor": {"e": "Monitor", "a": "المراقب"},
    "analyze": {"e": "Analyze", "a": "تحليل"},
    "recon": {"e": "Recon", "a": "استطلاع"},
    "reports": {"e": "Reports", "a": "التقارير"},
    "settings": {"e": "Settings", "a": "الإعدادات"},
    "sub": {"e": "Vulnerability Reporting AI", "a": "ذكاء اصطناعي لتقارير الثغرات"},
    "syst": {"e": "System Status", "a": "حالة النظام"},
    "ai": {"e": "AI Engine:", "a": "محرك الذكاء:"},
    "nocfg": {"e": "Not Configured", "a": "غير مُعدّ"},
    "reps": {"e": "Reports", "a": "تقارير"},
    "idle": {"e": "Idle", "a": "خامل"},
    "actv": {"e": "Active", "a": "نشط"},
    "nosess": {"e": "No active session", "a": "لا توجد جلسة"},
    "rec": {"e": "Recording...", "a": "جارٍ التسجيل..."},
    "qact": {"e": "Quick Actions", "a": "إجراءات سريعة"},
    "uchk": {"e": "Unable to check", "a": "تعذّر الفحص"},
    # Monitor
    "ghost": {"e": "Ghost Monitor", "a": "المراقب الشبحي"},
    "sesst": {"e": "Session Status", "a": "حالة الجلسة"},
    "start_ghost": {"e": "Start Ghost (-H)", "a": "بدء المراقب (-H)"},
    "start_hookall": {"e": "HookAll (-Ha)", "a": "تسجيل شامل (-Ha)"},
    "exclude": {"e": "Exclude This (-e)", "a": "استبعاد هذه (-e)"},
    "silent_mode": {"e": "Silent Mode", "a": "وضع صامت"},
    "stop_report": {"e": "Stop & Report (-R)", "a": "إيقاف وتقرير (-R)"},
    "stop_collect": {"e": "Stop & Collect", "a": "إيقاف وجمع"},
    "discard": {"e": "Discard", "a": "حذف"},
    "out": {"e": "Output", "a": "المخرجات"},
    "how": {"e": "How It Works", "a": "كيف يعمل"},
    "how_txt": {
        "e": ("Start Ghost (-H): Opens a terminal with recording enabled.\n"
              "HookAll (-Ha): Reads ALL open terminal sessions.\n"
              "Exclude (-e): Excludes current terminal from HookAll.\n"
              "Stop & Report (-R): Stops recording → generates AI report.\n"
              "Stop & Collect: Stops recording → saves data for Analyze page.\n\n"
              "Workflow:\n"
              "  1. Click 'Start Ghost' → terminal opens\n"
              "  2. Work inside it (nmap, nikto, sqlmap...)\n"
              "  3. Close terminal or click 'Stop & Collect'\n"
              "  4. Go to Analyze → Generate Report"),
        "a": ("بدء المراقب (-H): يفتح طرفية مع تسجيل.\n"
              "تسجيل شامل (-Ha): يقرأ كل الطرفيات المفتوحة.\n"
              "استبعاد (-e): يستبعد الطرفية الحالية من التسجيل الشامل.\n"
              "إيقاف وتقرير (-R): يوقف التسجيل ← يولّد تقرير AI.\n"
              "إيقاف وجمع: يوقف التسجيل ← يحفظ للتحليل.\n\n"
              "الخطوات:\n"
              "  1. اضغط 'بدء المراقب' ← تفتح طرفية\n"
              "  2. اشتغل داخلها\n"
              "  3. أغلقها أو اضغط 'إيقاف وجمع'\n"
              "  4. اذهب للتحليل ← ولّد التقرير"),
    },
    "stop_msg": {"e": "Stopping...", "a": "جارٍ الإيقاف..."},
    "capt": {"e": "✔ Captured {n} chars. Go to Analyze.", "a": "✔ التقاط {n} حرف. اذهب للتحليل."},
    "nosf": {"e": "No session data.", "a": "لا بيانات جلسة."},
    "disc": {"e": "Session discarded.", "a": "تم حذف الجلسة."},
    "noterm": {"e": "No terminal found!", "a": "لا طرفية!"},
    "hookall_reading": {"e": "Reading all open terminals...", "a": "جارٍ قراءة كل الطرفيات..."},
    "hookall_done": {"e": "✔ HookAll: Collected {n} chars from {t} terminals.", "a": "✔ تم جمع {n} حرف من {t} طرفية."},
    "hookall_none": {"e": "No open terminal sessions found.", "a": "لا توجد طرفيات مفتوحة."},
    "excluded": {"e": "Terminal excluded from HookAll.", "a": "تم استبعاد الطرفية."},
    # Analyze
    "anly": {"e": "Analyze & Generate Report", "a": "تحليل وتوليد تقرير"},
    "man": {"e": "Manual Input (-m)", "a": "إدخال يدوي (-m)"},
    "file": {"e": "File (-f)", "a": "ملف (-f)"},
    "gdata": {"e": "Ghost Data", "a": "بيانات المراقب"},
    "hist": {"e": "History (-p)", "a": "السجل (-p)"},
    "paste": {"e": "Paste terminal output...", "a": "الصق مخرجات الطرفية..."},
    "fpath": {"e": "File path (e.g. /home/user/scan.log)", "a": "مسار الملف"},
    "hlines": {"e": "Lines", "a": "أسطر"},
    "rtype": {"e": "Report Type", "a": "نوع التقرير"},
    "fmt": {"e": "Format (-F)", "a": "الصيغة (-F)"},
    "lang": {"e": "Language (-l)", "a": "اللغة (-l)"},
    "appr": {"e": "Approach (-A)", "a": "المنهج (-A)"},
    "defense": {"e": "Defense", "a": "دفاعي"},
    "offense": {"e": "Offense", "a": "هجومي"},
    "stype": {"e": "Scan Type (-S)", "a": "نوع الفحص (-S)"},
    "notify": {"e": "Telegram (-n)", "a": "تيليجرام (-n)"},
    "gen": {"e": "Generate Report", "a": "توليد التقرير"},
    "cdesc": {"e": "Custom description", "a": "وصف مخصّص"},
    "gening": {"e": "Generating...", "a": "جارٍ التوليد..."},
    "rsaved": {"e": "Report saved:", "a": "تم الحفظ:"},
    "rok": {"e": "Report generated!", "a": "تم توليد التقرير!"},
    "rfail": {"e": "Failed", "a": "فشل"},
    "nodata": {"e": "No data.", "a": "لا بيانات."},
    "nogd": {"e": "No Ghost data.", "a": "لا بيانات مراقب."},
    # Recon
    "rtitle": {"e": "Recon / OSINT (-r)", "a": "استطلاع / OSINT (-r)"},
    "tstat": {"e": "Tools Status", "a": "حالة الأدوات"},
    "tdom": {"e": "Target Domain", "a": "النطاق المستهدف"},
    "skip": {"e": "Skip Tools:", "a": "تخطّي أدوات:"},
    "rrun": {"e": "Run Recon", "a": "بدء الاستطلاع"},
    "rout": {"e": "Recon Output", "a": "مخرجات الاستطلاع"},
    "rrunning": {"e": "Running recon...", "a": "جارٍ الاستطلاع..."},
    "rdone": {"e": "Done!", "a": "اكتمل!"},
    "edom": {"e": "Enter domain", "a": "أدخل نطاقاً"},
    # Reports
    "arch": {"e": "Reports Archive (-Hy)", "a": "أرشيف التقارير (-Hy)"},
    "ref": {"e": "Refresh", "a": "تحديث"},
    "opf": {"e": "Open Folder", "a": "فتح المجلد"},
    "recreate": {"e": "Recreate Last (-Rc)", "a": "إعادة الأخير (-Rc)"},
    "norep": {"e": "No reports.", "a": "لا تقارير."},
    "sf": {"e": "{s} sessions, {f} files", "a": "{s} جلسة، {f} ملف"},
    "selrep": {"e": "Select a report", "a": "اختر تقريراً"},
    "rlist": {"e": "Sessions", "a": "الجلسات"},
    "bin": {"e": "(Binary — can't preview)", "a": "(ثنائي — لا يُعرض)"},
    "recreating": {"e": "Recreating last report...", "a": "جارٍ إعادة التوليد..."},
    "recreate_ok": {"e": "Report recreated!", "a": "تم إعادة التوليد!"},
    "recreate_no": {"e": "No cached data to recreate.", "a": "لا بيانات محفوظة لإعادة التوليد."},
    # Settings
    "stitle": {"e": "Settings (-Ch)", "a": "الإعدادات (-Ch)"},
    "prov": {"e": "Provider", "a": "المزود"},
    "akey": {"e": "API Key", "a": "مفتاح API"},
    "mname": {"e": "Model", "a": "النموذج"},
    "curl": {"e": "Custom URL", "a": "رابط مخصّص"},
    "tgn": {"e": "Telegram", "a": "تيليجرام"},
    "tgt": {"e": "Bot Token", "a": "توكن البوت"},
    "tgc": {"e": "Chat ID", "a": "معرّف المحادثة"},
    "integ": {"e": "Integrations", "a": "تكاملات"},
    "shk": {"e": "Shodan Key", "a": "مفتاح Shodan"},
    "save": {"e": "Save", "a": "حفظ"},
    "saved": {"e": "Saved!", "a": "تم الحفظ!"},
    "uilang": {"e": "Interface Language", "a": "لغة الواجهة"},
    # Diagnostics
    "diag": {"e": "Diagnostics (-Ck)", "a": "التشخيص (-Ck)"},
    "drun": {"e": "Running...", "a": "جارٍ..."},
    "ddone": {"e": "Done", "a": "اكتمل"},
}

LANGS = [
    "English", "Arabic", "French", "Spanish", "German", "Japanese", "Chinese",
    "Korean", "Russian", "Portuguese", "Italian", "Turkish", "Dutch", "Hindi",
]


# ══════════════════════════════════════════════════════════════════════
# LangManager
# ══════════════════════════════════════════════════════════════════════

class LangManager:
    """Manages the current interface language and provides translation lookup."""

    _map = {"e": "en", "a": "ar"}

    def __init__(self, default: str = "e"):
        self._variant = default  # "e" (English) or "a" (Arabic)

    @property
    def variant(self) -> str:
        return self._variant

    @variant.setter
    def variant(self, v: str) -> None:
        if v in ("e", "a"):
            self._variant = v

    def toggle(self) -> str:
        """Toggle between English and Arabic. Returns new variant."""
        self._variant = "a" if self._variant == "e" else "e"
        return self._variant

    def is_arabic(self) -> bool:
        return self._variant == "a"

    def t(self, key: str) -> str:
        """Translate a key to the current language."""
        entry = L.get(key, {})
        return entry.get(self._variant, entry.get("e", key))

    def report_language(self) -> str:
        """Return the language name for AI report generation."""
        return "Arabic" if self.is_arabic() else "English"

    def label_key(self) -> str:
        """Return 'a' or 'n' for report type label lookup."""
        return "a" if self.is_arabic() else "n"

    def display_name(self) -> str:
        """Return display name for the toggle button."""
        return "العربية" if self._variant == "e" else "English"
