"""
VURA Database Engine — SQLite Client & Scan Management
═══════════════════════════════════════════════════════
Replaces vura_clients_db.json with a proper SQLite database
that supports queries, relationships, and scales beyond 10 clients.

Database location: data/vura.db
Tables: clients, scans, licenses

Usage:
    from app.core.database import VuraDB

    db = VuraDB()
    db.add_client("ACME Corp", "acme.com", plan="pro")
    db.add_scan(client_id=1, target="acme.com", scan_type="recon")
    clients = db.list_clients(active_only=True)
    db.close()

    # أو باستخدام context manager:
    with VuraDB() as db:
        db.add_client("ACME Corp", "acme.com")
"""

import os
import json
import sqlite3
import datetime
import secrets
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()

# ─── Database Path ───────────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()
_DB_DIR       = _PROJECT_ROOT / "data"
_DB_PATH      = _DB_DIR / "vura.db"

# ─── Client Plans ────────────────────────────────────────────────────────────
VALID_PLANS = ("free", "pro_individual", "pro_team", "pro_enterprise",
               "max_individual", "max_team", "max_enterprise")

# ─── Scan Types ──────────────────────────────────────────────────────────────
VALID_SCAN_TYPES   = ("terminal", "recon", "executive", "dual", "manual", "file", "history")
VALID_SCAN_STATUSES = ("pending", "running", "completed", "failed", "cancelled")


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEMA — DDL Statements
# ═══════════════════════════════════════════════════════════════════════════════

_SCHEMA = """
-- ══════════════════════════════════════════════════════════════════════
-- CLIENTS — بيانات العملاء
-- ══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS clients (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    domain          TEXT,
    contact_email   TEXT,
    api_token       TEXT    UNIQUE,
    plan            TEXT    NOT NULL DEFAULT 'free',
    active          INTEGER NOT NULL DEFAULT 1,
    notes           TEXT,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_clients_domain ON clients(domain);
CREATE INDEX IF NOT EXISTS idx_clients_api_token ON clients(api_token);
CREATE INDEX IF NOT EXISTS idx_clients_active ON clients(active);

-- ══════════════════════════════════════════════════════════════════════
-- SCANS — سجل عمليات الفحص
-- ══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id       INTEGER,
    target          TEXT    NOT NULL,
    scan_type       TEXT    NOT NULL DEFAULT 'terminal',
    approach        TEXT    NOT NULL DEFAULT 'defense',
    language        TEXT    NOT NULL DEFAULT 'English',
    status          TEXT    NOT NULL DEFAULT 'pending',
    report_md       TEXT,
    report_pdf      TEXT,
    report_json     TEXT,
    script_path     TEXT,
    findings_count  INTEGER DEFAULT 0,
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    low_count       INTEGER DEFAULT 0,
    error_message   TEXT,
    created_at      TEXT    NOT NULL,
    completed_at    TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_client ON scans(client_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);

-- ══════════════════════════════════════════════════════════════════════
-- LICENSES — سجل التراخيص (استيراد من JSON القديم)
-- ══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS licenses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hwid            TEXT    NOT NULL UNIQUE,
    client_id       INTEGER,
    activation_date TEXT    NOT NULL,
    expiration_date TEXT    NOT NULL DEFAULT 'Lifetime',
    revoked         INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_licenses_hwid ON licenses(hwid);
"""


# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class VuraDB:
    """
    مدير قاعدة بيانات VURA — يغلّف SQLite بواجهة نظيفة.
    يدعم context manager (with statement).
    """

    def __init__(self, db_path=None):
        self.db_path = Path(db_path) if db_path else _DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # النتائج كـ dict-like objects
        self.conn.execute("PRAGMA journal_mode=WAL")  # أداء أفضل للكتابة المتزامنة
        self.conn.execute("PRAGMA foreign_keys=ON")    # تفعيل العلاقات

        self._init_schema()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _init_schema(self):
        """إنشاء الجداول إذا لم تكن موجودة."""
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self):
        """إغلاق الاتصال بقاعدة البيانات."""
        if self.conn:
            self.conn.close()
            self.conn = None

    def _now(self):
        """الوقت الحالي بصيغة موحّدة."""
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ═══════════════════════════════════════════════════════════════════════
    # CLIENT MANAGEMENT
    # ═══════════════════════════════════════════════════════════════════════

    def add_client(self, name, domain=None, contact_email=None, plan="free", notes=None):
        """
        إضافة عميل جديد مع توليد API token تلقائي.

        Parameters:
            name          : اسم العميل أو الشركة
            domain        : الدومين الرئيسي (e.g., "example.com")
            contact_email : بريد التواصل
            plan          : نوع الباقة — free, starter, pro, enterprise, white-label
            notes         : ملاحظات إضافية

        Returns:
            dict: بيانات العميل المُنشأ مع api_token
        """
        if plan not in VALID_PLANS:
            raise ValueError(f"Invalid plan '{plan}'. Valid: {', '.join(VALID_PLANS)}")

        api_token = f"vura_{secrets.token_hex(24)}"
        now = self._now()

        cursor = self.conn.execute(
            """INSERT INTO clients (name, domain, contact_email, api_token, plan, active, notes, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)""",
            (name, domain, contact_email, api_token, plan, notes, now, now)
        )
        self.conn.commit()

        client_id = cursor.lastrowid
        console.print(f"[green][+] Client added: {name} (ID: {client_id}, Plan: {plan})[/green]")

        return self._row_to_dict(self.get_client(client_id))

    def get_client(self, client_id):
        """جلب عميل بالـ ID."""
        row = self.conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
        return row

    def get_client_by_token(self, api_token):
        """جلب عميل بالـ API token — يُستخدم في الـ REST API."""
        row = self.conn.execute("SELECT * FROM clients WHERE api_token = ?", (api_token,)).fetchone()
        return row

    def get_client_by_domain(self, domain):
        """جلب عميل بالدومين."""
        row = self.conn.execute("SELECT * FROM clients WHERE domain = ?", (domain,)).fetchone()
        return row

    def list_clients(self, active_only=False, plan=None):
        """
        قائمة العملاء مع فلترة اختيارية.

        Parameters:
            active_only : True = فقط العملاء النشطين
            plan        : فلترة حسب الباقة

        Returns:
            list[dict]
        """
        query = "SELECT * FROM clients WHERE 1=1"
        params = []

        if active_only:
            query += " AND active = 1"
        if plan:
            query += " AND plan = ?"
            params.append(plan)

        query += " ORDER BY created_at DESC"
        rows = self.conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def update_client(self, client_id, **kwargs):
        """
        تحديث بيانات عميل.

        Parameters:
            client_id : ID العميل
            **kwargs  : الحقول المراد تحديثها (name, domain, plan, active, notes, contact_email)

        Returns:
            bool: True إذا تم التحديث
        """
        allowed = {"name", "domain", "contact_email", "plan", "active", "notes"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}

        if not updates:
            return False

        if "plan" in updates and updates["plan"] not in VALID_PLANS:
            raise ValueError(f"Invalid plan '{updates['plan']}'. Valid: {', '.join(VALID_PLANS)}")

        updates["updated_at"] = self._now()

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [client_id]

        self.conn.execute(f"UPDATE clients SET {set_clause} WHERE id = ?", values)
        self.conn.commit()
        return True

    def deactivate_client(self, client_id):
        """تعطيل عميل (بدون حذف)."""
        return self.update_client(client_id, active=0)

    def activate_client(self, client_id):
        """إعادة تفعيل عميل."""
        return self.update_client(client_id, active=1)

    def delete_client(self, client_id, confirm=False):
        """
        حذف عميل نهائياً — يحتاج confirm=True.
        الفحوصات المرتبطة تبقى (client_id يصبح NULL).
        """
        if not confirm:
            console.print("[yellow][!] Use delete_client(id, confirm=True) to permanently delete.[/yellow]")
            return False

        self.conn.execute("DELETE FROM clients WHERE id = ?", (client_id,))
        self.conn.commit()
        return True

    def regenerate_token(self, client_id):
        """توليد API token جديد للعميل (يُلغي القديم)."""
        new_token = f"vura_{secrets.token_hex(24)}"
        self.conn.execute(
            "UPDATE clients SET api_token = ?, updated_at = ? WHERE id = ?",
            (new_token, self._now(), client_id)
        )
        self.conn.commit()
        return new_token

    # ═══════════════════════════════════════════════════════════════════════
    # SCAN MANAGEMENT
    # ═══════════════════════════════════════════════════════════════════════

    def add_scan(self, target, scan_type="terminal", approach="defense",
                 language="English", client_id=None):
        """
        تسجيل فحص جديد.

        Returns:
            int: scan_id
        """
        if scan_type not in VALID_SCAN_TYPES:
            scan_type = "terminal"  # fallback آمن

        now = self._now()
        cursor = self.conn.execute(
            """INSERT INTO scans (client_id, target, scan_type, approach, language, status, created_at)
               VALUES (?, ?, ?, ?, ?, 'running', ?)""",
            (client_id, target, scan_type, approach, language, now)
        )
        self.conn.commit()
        return cursor.lastrowid

    def complete_scan(self, scan_id, report_md=None, report_pdf=None, report_json=None,
                      script_path=None, findings_count=0, critical_count=0,
                      high_count=0, medium_count=0, low_count=0):
        """
        تحديث فحص بعد اكتماله بنجاح.
        """
        self.conn.execute(
            """UPDATE scans SET
                status = 'completed', completed_at = ?,
                report_md = ?, report_pdf = ?, report_json = ?, script_path = ?,
                findings_count = ?, critical_count = ?, high_count = ?,
                medium_count = ?, low_count = ?
            WHERE id = ?""",
            (self._now(), report_md, report_pdf, report_json, script_path,
             findings_count, critical_count, high_count, medium_count, low_count,
             scan_id)
        )
        self.conn.commit()

    def fail_scan(self, scan_id, error_message="Unknown error"):
        """تسجيل فشل فحص."""
        self.conn.execute(
            "UPDATE scans SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?",
            (error_message, self._now(), scan_id)
        )
        self.conn.commit()

    def get_scan(self, scan_id):
        """جلب فحص بالـ ID."""
        row = self.conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return self._row_to_dict(row) if row else None

    def list_scans(self, client_id=None, status=None, scan_type=None, limit=50):
        """
        قائمة الفحوصات مع فلترة.

        Parameters:
            client_id : فلترة حسب العميل
            status    : فلترة حسب الحالة (pending, running, completed, failed)
            scan_type : فلترة حسب النوع
            limit     : الحد الأقصى للنتائج

        Returns:
            list[dict]
        """
        query = "SELECT * FROM scans WHERE 1=1"
        params = []

        if client_id is not None:
            query += " AND client_id = ?"
            params.append(client_id)
        if status:
            query += " AND status = ?"
            params.append(status)
        if scan_type:
            query += " AND scan_type = ?"
            params.append(scan_type)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_client_stats(self, client_id):
        """
        إحصائيات فحوصات عميل معيّن.

        Returns:
            dict: {total_scans, completed, failed, total_findings, critical, high, medium, low}
        """
        row = self.conn.execute(
            """SELECT
                COUNT(*)                   AS total_scans,
                SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) AS completed,
                SUM(CASE WHEN status='failed'    THEN 1 ELSE 0 END) AS failed,
                COALESCE(SUM(findings_count), 0) AS total_findings,
                COALESCE(SUM(critical_count), 0) AS critical,
                COALESCE(SUM(high_count), 0)     AS high,
                COALESCE(SUM(medium_count), 0)   AS medium,
                COALESCE(SUM(low_count), 0)      AS low
            FROM scans WHERE client_id = ?""",
            (client_id,)
        ).fetchone()

        return self._row_to_dict(row) if row else {}

    def get_global_stats(self):
        """
        إحصائيات عامة — كل العملاء والفحوصات.

        Returns:
            dict: {total_clients, active_clients, total_scans, ...}
        """
        clients = self.conn.execute(
            """SELECT
                COUNT(*)                                              AS total_clients,
                SUM(CASE WHEN active=1 THEN 1 ELSE 0 END)            AS active_clients
            FROM clients"""
        ).fetchone()

        scans = self.conn.execute(
            """SELECT
                COUNT(*)                                              AS total_scans,
                SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END)  AS completed_scans,
                SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END)     AS failed_scans,
                COALESCE(SUM(findings_count), 0)                      AS total_findings,
                COALESCE(SUM(critical_count), 0)                      AS total_critical
            FROM scans"""
        ).fetchone()

        result = {}
        if clients:
            result.update(self._row_to_dict(clients))
        if scans:
            result.update(self._row_to_dict(scans))
        return result

    # ═══════════════════════════════════════════════════════════════════════
    # LICENSE MANAGEMENT
    # ═══════════════════════════════════════════════════════════════════════

    def add_license(self, hwid, client_id=None, expiration_date="Lifetime"):
        """تسجيل ترخيص جديد."""
        now = self._now()
        try:
            self.conn.execute(
                """INSERT INTO licenses (hwid, client_id, activation_date, expiration_date, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (hwid, client_id, now, expiration_date, now)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            # HWID موجود مسبقاً — تحديث بدلاً من إضافة
            self.conn.execute(
                "UPDATE licenses SET client_id = ?, expiration_date = ? WHERE hwid = ?",
                (client_id, expiration_date, hwid)
            )
            self.conn.commit()
            return True

    def revoke_license(self, hwid):
        """إلغاء ترخيص."""
        self.conn.execute("UPDATE licenses SET revoked = 1 WHERE hwid = ?", (hwid,))
        self.conn.commit()

    def is_license_valid(self, hwid):
        """فحص صلاحية ترخيص بالـ HWID."""
        row = self.conn.execute(
            "SELECT * FROM licenses WHERE hwid = ? AND revoked = 0", (hwid,)
        ).fetchone()

        if not row:
            return False

        exp = row["expiration_date"]
        if exp == "Lifetime":
            return True

        try:
            exp_date = datetime.datetime.strptime(exp, "%Y-%m-%d %H:%M:%S")
            return datetime.datetime.now() <= exp_date
        except ValueError:
            return False

    def list_licenses(self):
        """قائمة كل التراخيص."""
        rows = self.conn.execute(
            "SELECT * FROM licenses ORDER BY created_at DESC"
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ═══════════════════════════════════════════════════════════════════════
    # MIGRATION — استيراد من JSON القديم
    # ═══════════════════════════════════════════════════════════════════════

    def migrate_from_json(self, json_path=None):
        """
        استيراد بيانات vura_clients_db.json إلى SQLite.
        يُشغّل مرة واحدة فقط — آمن لإعادة التشغيل (يتخطى الموجود).

        Parameters:
            json_path : مسار ملف JSON (افتراضي: vura_clients_db.json في جذر المشروع)

        Returns:
            int: عدد السجلات المستوردة
        """
        if not json_path:
            json_path = str(_PROJECT_ROOT / "vura_clients_db.json")

        if not Path(json_path).exists():
            console.print(f"[dim yellow][~] No JSON database found at {json_path} — skipping migration.[/dim yellow]")
            return 0

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            console.print(f"[red][!] Failed to read JSON: {e}[/red]")
            return 0

        if not isinstance(data, list):
            console.print("[red][!] JSON format not recognized — expected a list.[/red]")
            return 0

        imported = 0
        for entry in data:
            hwid = entry.get("hwid", "").strip()
            if not hwid:
                continue

            activation  = entry.get("activation_date", self._now())
            expiration  = entry.get("expiration_date", "Lifetime")

            try:
                self.conn.execute(
                    """INSERT OR IGNORE INTO licenses (hwid, activation_date, expiration_date, created_at)
                       VALUES (?, ?, ?, ?)""",
                    (hwid, activation, expiration, self._now())
                )
                imported += 1
            except Exception:
                continue

        self.conn.commit()

        if imported > 0:
            console.print(f"[green][+] Migration complete: {imported} license(s) imported from JSON to SQLite.[/green]")

        return imported

    # ═══════════════════════════════════════════════════════════════════════
    # DISPLAY — عرض البيانات في Terminal
    # ═══════════════════════════════════════════════════════════════════════

    def show_clients(self):
        """عرض جدول العملاء في Terminal."""
        clients = self.list_clients()

        if not clients:
            console.print("[yellow][!] No clients found. Use db.add_client() to add one.[/yellow]")
            return

        table = Table(title="VURA Clients", show_header=True, header_style="bold magenta")
        table.add_column("ID", justify="center", style="bold")
        table.add_column("Name", style="cyan")
        table.add_column("Domain")
        table.add_column("Plan", justify="center")
        table.add_column("Status", justify="center")
        table.add_column("Scans", justify="center")
        table.add_column("Created")

        for c in clients:
            stats = self.get_client_stats(c["id"])
            status = "[green]Active[/green]" if c["active"] else "[red]Inactive[/red]"
            plan_colors = {"free": "white", "pro_individual": "cyan", "pro_team": "cyan",
                          "pro_enterprise": "green", "max_individual": "yellow", "max_team": "yellow",
                          "max_enterprise": "magenta"}
            plan_color = plan_colors.get(c["plan"], "white")

            table.add_row(
                str(c["id"]),
                c["name"],
                c.get("domain") or "—",
                f"[{plan_color}]{c['plan']}[/{plan_color}]",
                status,
                str(stats.get("total_scans", 0)),
                c["created_at"][:10],
            )

        console.print(table)

    def show_scans(self, client_id=None, limit=20):
        """عرض جدول الفحوصات في Terminal."""
        scans = self.list_scans(client_id=client_id, limit=limit)

        if not scans:
            console.print("[yellow][!] No scans found.[/yellow]")
            return

        table = Table(title="VURA Scan History", show_header=True, header_style="bold magenta")
        table.add_column("ID", justify="center", style="bold")
        table.add_column("Target", style="cyan")
        table.add_column("Type", justify="center")
        table.add_column("Status", justify="center")
        table.add_column("Findings", justify="center")
        table.add_column("Critical", justify="center")
        table.add_column("Date")

        status_colors = {
            "completed": "green", "failed": "red",
            "running": "yellow", "pending": "dim",
        }

        for s in scans:
            color = status_colors.get(s["status"], "white")
            table.add_row(
                str(s["id"]),
                s["target"][:30],
                s["scan_type"],
                f"[{color}]{s['status']}[/{color}]",
                str(s.get("findings_count") or 0),
                str(s.get("critical_count") or 0),
                s["created_at"][:16],
            )

        console.print(table)

    def show_stats(self):
        """عرض إحصائيات عامة في Terminal."""
        stats = self.get_global_stats()

        if not stats:
            console.print("[yellow][!] No data yet.[/yellow]")
            return

        table = Table(title="VURA Dashboard Stats", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="bold cyan")
        table.add_column("Value", justify="right", style="bold white")

        table.add_row("Total Clients",     str(stats.get("total_clients", 0)))
        table.add_row("Active Clients",    str(stats.get("active_clients", 0)))
        table.add_row("Total Scans",       str(stats.get("total_scans", 0)))
        table.add_row("Completed Scans",   str(stats.get("completed_scans", 0)))
        table.add_row("Failed Scans",      str(stats.get("failed_scans", 0)))
        table.add_row("Total Findings",    str(stats.get("total_findings", 0)))
        table.add_row("Critical Findings", f"[red]{stats.get('total_critical', 0)}[/red]")

        console.print(table)

    # ═══════════════════════════════════════════════════════════════════════
    # UTILITIES
    # ═══════════════════════════════════════════════════════════════════════

    def _row_to_dict(self, row):
        """تحويل sqlite3.Row إلى dict عادي."""
        if row is None:
            return None
        return dict(row)

    def search_clients(self, query):
        """
        بحث في العملاء بالاسم أو الدومين أو البريد.

        Returns:
            list[dict]
        """
        pattern = f"%{query}%"
        rows = self.conn.execute(
            """SELECT * FROM clients
               WHERE name LIKE ? OR domain LIKE ? OR contact_email LIKE ?
               ORDER BY created_at DESC""",
            (pattern, pattern, pattern)
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def export_to_json(self, output_path=None):
        """
        تصدير كل البيانات إلى JSON — نسخة احتياطية.

        Returns:
            str: مسار الملف المُصدَّر
        """
        if not output_path:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(_DB_DIR / f"vura_backup_{timestamp}.json")

        data = {
            "exported_at": self._now(),
            "clients":  self.list_clients(),
            "scans":    self.list_scans(limit=9999),
            "licenses": self.list_licenses(),
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        console.print(f"[green][+] Database exported to: {output_path}[/green]")
        return output_path


# ═══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS — للاستخدام السريع بدون إنشاء instance
# ═══════════════════════════════════════════════════════════════════════════════

def init_db():
    """تهيئة قاعدة البيانات — يُستدعى مرة عند أول تشغيل."""
    with VuraDB() as db:
        console.print(f"[green][+] VURA database initialized: {db.db_path}[/green]")
        return db.db_path


def migrate_json_to_sqlite():
    """استيراد بيانات JSON القديمة إلى SQLite."""
    with VuraDB() as db:
        return db.migrate_from_json()


def get_db():
    """
    إنشاء اتصال جديد بقاعدة البيانات.
    تذكّر إغلاقه بـ db.close() أو استخدم with statement.
    """
    return VuraDB()
