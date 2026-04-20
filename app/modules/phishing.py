"""
VURA Phishing Module — GoPhish Integration & Campaign Management
════════════════════════════════════════════════════════════════════
Manages phishing simulation campaigns through GoPhish API.
Creates campaigns, tracks results, and generates awareness reports.

Dependencies:
    - requests (already in requirements.txt)
    - GoPhish server running (default: https://localhost:3333)

Setup:
    Add to config.json:
        "gophish_api_key": "your_gophish_api_key",
        "gophish_url": "https://localhost:3333"

Usage:
    from app.modules.phishing import VuraPhishing

    gp = VuraPhishing()
    gp.create_campaign(
        name="Q1 Security Awareness",
        template_name="Password Reset",
        targets=[{"email": "user@company.com", "first_name": "Ahmed"}],
        sending_profile_id=1,
    )
    results = gp.get_campaign_results(campaign_id=1)
    report = gp.generate_phishing_report(campaign_id=1)
"""

import os
import json
import datetime
from pathlib import Path
import requests
import urllib3
from rich.console import Console
from rich.table import Table

console = Console()

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _load_gophish_config():
    """تحميل إعدادات GoPhish من config.json."""
    config_path = _PROJECT_ROOT / "config.json"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        return {
            "api_key": config.get("gophish_api_key", "").strip(),
            "url":     config.get("gophish_url", "https://localhost:3333").strip().rstrip("/"),
        }
    except (json.JSONDecodeError, IOError):
        return {"api_key": "", "url": "https://localhost:3333"}


class VuraPhishing:
    """
    إدارة حملات التصيّد عبر GoPhish API.
    """

    def __init__(self, api_key=None, gophish_url=None, verify_ssl=None):
        config = _load_gophish_config()
        self.api_key = api_key or config["api_key"]
        self.base_url = gophish_url or config["url"]
        self.headers = {"Authorization": f"Bearer {self.api_key}"}

        # Default: verify TLS for remote hosts, allow self-signed ONLY for local
        # GoPhish (which ships with a self-signed cert by default). Callers can
        # still opt in/out explicitly via the constructor arg.
        if verify_ssl is None:
            parsed = urllib3.util.parse_url(self.base_url)
            host = (parsed.host or "").lower()
            verify_ssl = host not in ("localhost", "127.0.0.1", "::1")
        self.verify_ssl = verify_ssl

        # Only silence InsecureRequestWarning when we are explicitly skipping
        # verification — keep it loud for every other requests.* consumer.
        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if not self.api_key:
            console.print(
                "[dim yellow][!] VURA Phishing: No gophish_api_key in config.json. "
                "Phishing features disabled.[/dim yellow]"
            )

    def is_configured(self):
        """هل GoPhish مُعدّ."""
        return bool(self.api_key)

    def _request(self, method, endpoint, data=None):
        """طلب موحّد لـ GoPhish API."""
        if not self.is_configured():
            return {"error": "GoPhish not configured. Add gophish_api_key to config.json."}

        url = f"{self.base_url}/api/{endpoint}"

        try:
            resp = requests.request(
                method, url,
                headers=self.headers,
                json=data,
                verify=self.verify_ssl,
                timeout=30,
            )

            if resp.status_code == 401:
                return {"error": "GoPhish API key is invalid (401)."}

            if resp.status_code == 404:
                return {"error": f"GoPhish endpoint not found: {endpoint}"}

            if resp.status_code >= 400:
                return {"error": f"GoPhish error {resp.status_code}: {resp.text[:200]}"}

            return resp.json()

        except requests.exceptions.ConnectionError:
            return {"error": f"Cannot connect to GoPhish at {self.base_url}. Is it running?"}
        except requests.exceptions.Timeout:
            return {"error": "GoPhish request timed out."}
        except Exception as e:
            return {"error": f"GoPhish error: {str(e)}"}

    # ═══════════════════════════════════════════════════════════════════════
    # CONNECTION TEST
    # ═══════════════════════════════════════════════════════════════════════

    def test_connection(self):
        """فحص الاتصال بـ GoPhish."""
        result = self._request("GET", "campaigns/?api_key=" + self.api_key)

        if "error" in result:
            console.print(f"[red]  ✘ GoPhish: {result['error']}[/red]")
            return False

        console.print(f"[green]  ✓ GoPhish connected at {self.base_url}[/green]")
        return True

    # ═══════════════════════════════════════════════════════════════════════
    # TEMPLATES — قوالب رسائل التصيّد
    # ═══════════════════════════════════════════════════════════════════════

    def list_templates(self):
        """قائمة قوالب الرسائل."""
        result = self._request("GET", "templates/")
        if isinstance(result, dict) and "error" in result:
            return result
        return result if isinstance(result, list) else []

    def create_template(self, name, subject, html_body, text_body=""):
        """
        إنشاء قالب رسالة تصيّد.

        Parameters:
            name      : اسم القالب
            subject   : عنوان الرسالة
            html_body : محتوى HTML
            text_body : محتوى نصي بديل
        """
        data = {
            "name": name,
            "subject": subject,
            "html": html_body,
            "text": text_body,
        }
        result = self._request("POST", "templates/", data)

        if isinstance(result, dict) and "error" not in result:
            console.print(f"[green][+] Template created: {name} (ID: {result.get('id')})[/green]")

        return result

    def get_template(self, template_id):
        """جلب قالب بالـ ID."""
        return self._request("GET", f"templates/{template_id}")

    # ═══════════════════════════════════════════════════════════════════════
    # GROUPS — مجموعات الأهداف
    # ═══════════════════════════════════════════════════════════════════════

    def list_groups(self):
        """قائمة مجموعات الأهداف."""
        result = self._request("GET", "groups/")
        if isinstance(result, dict) and "error" in result:
            return result
        return result if isinstance(result, list) else []

    def create_group(self, name, targets):
        """
        إنشاء مجموعة أهداف.

        Parameters:
            name    : اسم المجموعة
            targets : قائمة أهداف — [{"email": "x@y.com", "first_name": "Ahmed", "last_name": "Ali", "position": "Developer"}]
        """
        data = {
            "name": name,
            "targets": targets,
        }
        result = self._request("POST", "groups/", data)

        if isinstance(result, dict) and "error" not in result:
            count = len(targets)
            console.print(f"[green][+] Group created: {name} ({count} targets, ID: {result.get('id')})[/green]")

        return result

    def import_targets_from_csv(self, name, csv_path):
        """
        استيراد أهداف من ملف CSV.
        الأعمدة المطلوبة: email, first_name, last_name, position (اختياري)
        """
        import csv

        if not os.path.exists(csv_path):
            return {"error": f"CSV file not found: {csv_path}"}

        targets = []
        try:
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    target = {"email": row.get("email", "").strip()}
                    if not target["email"]:
                        continue
                    if row.get("first_name"):
                        target["first_name"] = row["first_name"].strip()
                    if row.get("last_name"):
                        target["last_name"] = row["last_name"].strip()
                    if row.get("position"):
                        target["position"] = row["position"].strip()
                    targets.append(target)
        except Exception as e:
            return {"error": f"CSV parsing error: {str(e)}"}

        if not targets:
            return {"error": "No valid targets found in CSV"}

        return self.create_group(name, targets)

    # ═══════════════════════════════════════════════════════════════════════
    # SENDING PROFILES — إعدادات الإرسال
    # ═══════════════════════════════════════════════════════════════════════

    def list_sending_profiles(self):
        """قائمة Sending Profiles."""
        result = self._request("GET", "smtp/")
        if isinstance(result, dict) and "error" in result:
            return result
        return result if isinstance(result, list) else []

    def create_sending_profile(self, name, from_address, smtp_host, smtp_port=587,
                                username="", password="", ignore_cert=True):
        """
        إنشاء Sending Profile.

        Parameters:
            name         : اسم البروفايل
            from_address : عنوان المرسل (e.g., "IT Security <security@company.com>")
            smtp_host    : SMTP server
            smtp_port    : Port (587 TLS, 465 SSL, 25 plain)
            username     : SMTP username
            password     : SMTP password
        """
        data = {
            "name": name,
            "from_address": from_address,
            "host": f"{smtp_host}:{smtp_port}",
            "username": username,
            "password": password,
            "ignore_cert_errors": ignore_cert,
        }
        result = self._request("POST", "smtp/", data)

        if isinstance(result, dict) and "error" not in result:
            console.print(f"[green][+] Sending Profile created: {name} (ID: {result.get('id')})[/green]")

        return result

    # ═══════════════════════════════════════════════════════════════════════
    # LANDING PAGES — صفحات الهبوط
    # ═══════════════════════════════════════════════════════════════════════

    def list_landing_pages(self):
        """قائمة صفحات الهبوط."""
        result = self._request("GET", "pages/")
        if isinstance(result, dict) and "error" in result:
            return result
        return result if isinstance(result, list) else []

    def create_landing_page(self, name, html_content, capture_credentials=True, redirect_url=""):
        """إنشاء صفحة هبوط."""
        data = {
            "name": name,
            "html": html_content,
            "capture_credentials": capture_credentials,
            "redirect_url": redirect_url,
        }
        result = self._request("POST", "pages/", data)

        if isinstance(result, dict) and "error" not in result:
            console.print(f"[green][+] Landing Page created: {name} (ID: {result.get('id')})[/green]")

        return result

    # ═══════════════════════════════════════════════════════════════════════
    # CAMPAIGNS — الحملات
    # ═══════════════════════════════════════════════════════════════════════

    def list_campaigns(self):
        """قائمة كل الحملات."""
        result = self._request("GET", "campaigns/")
        if isinstance(result, dict) and "error" in result:
            return result
        return result if isinstance(result, list) else []

    def create_campaign(self, name, template_id, group_id, page_id,
                         sending_profile_id, url, launch_date=None):
        """
        إطلاق حملة تصيّد جديدة.

        Parameters:
            name               : اسم الحملة
            template_id        : ID قالب الرسالة
            group_id           : ID مجموعة الأهداف
            page_id            : ID صفحة الهبوط
            sending_profile_id : ID بروفايل الإرسال
            url                : رابط صفحة الهبوط الظاهر في الرسالة
            launch_date        : تاريخ الإطلاق (None = فوري)
        """
        if not launch_date:
            launch_date = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")

        data = {
            "name": name,
            "template": {"id": template_id},
            "groups": [{"id": group_id}],
            "page": {"id": page_id},
            "smtp": {"id": sending_profile_id},
            "url": url,
            "launch_date": launch_date,
        }

        result = self._request("POST", "campaigns/", data)

        if isinstance(result, dict) and "error" not in result:
            console.print(f"[bold green][+] Campaign launched: {name} (ID: {result.get('id')})[/bold green]")

        return result

    def get_campaign(self, campaign_id):
        """جلب تفاصيل حملة."""
        return self._request("GET", f"campaigns/{campaign_id}")

    def get_campaign_results(self, campaign_id):
        """جلب نتائج حملة (من فتح، من نقر، من أدخل بيانات)."""
        return self._request("GET", f"campaigns/{campaign_id}/results")

    def complete_campaign(self, campaign_id):
        """إنهاء حملة."""
        return self._request("DELETE", f"campaigns/{campaign_id}")

    # ═══════════════════════════════════════════════════════════════════════
    # REPORTING — تقرير نتائج الحملة
    # ═══════════════════════════════════════════════════════════════════════

    def generate_phishing_report(self, campaign_id, language="English"):
        """
        توليد تقرير نتائج حملة تصيّد بالـ AI.

        يجلب نتائج الحملة من GoPhish، يحوّلها لنص،
        ثم يُرسلها لـ ai_engine بـ prompt مخصص.

        Parameters:
            campaign_id : ID الحملة
            language    : لغة التقرير

        Returns:
            str: محتوى التقرير (Markdown)
        """
        campaign = self.get_campaign(campaign_id)
        if isinstance(campaign, dict) and "error" in campaign:
            return f"# Error\n{campaign['error']}"

        results = self.get_campaign_results(campaign_id)
        if isinstance(results, dict) and "error" in results:
            return f"# Error\n{results['error']}"

        # ── تحليل النتائج ──
        stats = self._analyze_campaign(campaign, results)

        # ── تجهيز البيانات للـ AI ──
        report_data = self._format_campaign_data(campaign, stats)

        # ── توليد التقرير ──
        from app.core.ai_engine import generate_report

        phishing_prompt_data = (
            f"=== PHISHING CAMPAIGN RESULTS ===\n\n"
            f"{report_data}\n\n"
            f"=== END OF DATA ===\n\n"
            f"Generate a professional phishing awareness assessment report. "
            f"Include: campaign overview, click rate analysis, risk assessment, "
            f"department breakdown if available, and security awareness recommendations."
        )

        return generate_report(
            phishing_prompt_data,
            language=language,
            output_format="md",
            approach="defense",
            include_script=False,
            scan_type="executive",  # نستخدم executive style — بلغة أعمال
        )

    def _analyze_campaign(self, campaign, results):
        """تحليل إحصائي لنتائج الحملة."""
        timeline = results if isinstance(results, list) else results.get("timeline", [])
        campaign_results = campaign.get("results", [])

        total_targets = len(campaign_results)
        emails_sent = sum(1 for r in campaign_results if r.get("status") in ("Email Sent", "Email Opened", "Clicked Link", "Submitted Data"))
        emails_opened = sum(1 for r in campaign_results if r.get("status") in ("Email Opened", "Clicked Link", "Submitted Data"))
        links_clicked = sum(1 for r in campaign_results if r.get("status") in ("Clicked Link", "Submitted Data"))
        data_submitted = sum(1 for r in campaign_results if r.get("status") == "Submitted Data")
        reported = sum(1 for r in campaign_results if r.get("status") == "Email Reported")

        stats = {
            "total_targets": total_targets,
            "emails_sent": emails_sent,
            "emails_opened": emails_opened,
            "links_clicked": links_clicked,
            "data_submitted": data_submitted,
            "reported": reported,
            "open_rate": round((emails_opened / max(emails_sent, 1)) * 100, 1),
            "click_rate": round((links_clicked / max(emails_sent, 1)) * 100, 1),
            "submit_rate": round((data_submitted / max(emails_sent, 1)) * 100, 1),
            "report_rate": round((reported / max(emails_sent, 1)) * 100, 1),
        }

        # ── Risk Level ──
        if stats["submit_rate"] > 30:
            stats["risk_level"] = "CRITICAL"
        elif stats["click_rate"] > 40:
            stats["risk_level"] = "HIGH"
        elif stats["click_rate"] > 20:
            stats["risk_level"] = "MEDIUM"
        else:
            stats["risk_level"] = "LOW"

        return stats

    def _format_campaign_data(self, campaign, stats):
        """تنسيق بيانات الحملة كنص للـ AI."""
        name = campaign.get("name", "Unknown")
        created = campaign.get("created_date", "Unknown")
        status = campaign.get("status", "Unknown")

        text = f"""Campaign Name: {name}
Campaign Status: {status}
Created: {created}

=== STATISTICS ===
Total Targets: {stats['total_targets']}
Emails Sent: {stats['emails_sent']}
Emails Opened: {stats['emails_opened']} ({stats['open_rate']}%)
Links Clicked: {stats['links_clicked']} ({stats['click_rate']}%)
Credentials Submitted: {stats['data_submitted']} ({stats['submit_rate']}%)
Emails Reported: {stats['reported']} ({stats['report_rate']}%)
Overall Risk Level: {stats['risk_level']}

=== ANALYSIS ===
- Open Rate: {stats['open_rate']}% — {'DANGEROUS: Most users opened the phishing email' if stats['open_rate'] > 50 else 'Moderate awareness'}
- Click Rate: {stats['click_rate']}% — {'CRITICAL: High number of users clicked the malicious link' if stats['click_rate'] > 30 else 'Acceptable but needs improvement'}
- Submit Rate: {stats['submit_rate']}% — {'CRITICAL: Users are submitting credentials to fake pages' if stats['submit_rate'] > 10 else 'Low credential compromise'}
- Report Rate: {stats['report_rate']}% — {'GOOD: Users are reporting suspicious emails' if stats['report_rate'] > 20 else 'POOR: Users are not reporting phishing attempts'}
"""

        # ── تفاصيل كل هدف ──
        campaign_results = campaign.get("results", [])
        if campaign_results:
            text += "\n=== PER-TARGET RESULTS ===\n"
            for r in campaign_results[:50]:  # أول 50 فقط
                email = r.get("email", "unknown")
                status_val = r.get("status", "unknown")
                text += f"  - {email}: {status_val}\n"

            if len(campaign_results) > 50:
                text += f"  ... and {len(campaign_results) - 50} more targets\n"

        return text

    # ═══════════════════════════════════════════════════════════════════════
    # DISPLAY — عرض في Terminal
    # ═══════════════════════════════════════════════════════════════════════

    def show_campaigns(self):
        """عرض جدول الحملات."""
        campaigns = self.list_campaigns()
        if isinstance(campaigns, dict) and "error" in campaigns:
            console.print(f"[red]{campaigns['error']}[/red]")
            return

        if not campaigns:
            console.print("[yellow][!] No campaigns found.[/yellow]")
            return

        table = Table(title="VURA Phishing Campaigns", show_header=True, header_style="bold magenta")
        table.add_column("ID", justify="center", style="bold")
        table.add_column("Name", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Targets", justify="center")
        table.add_column("Clicked", justify="center")
        table.add_column("Submitted", justify="center")
        table.add_column("Created")

        for c in campaigns:
            results = c.get("results", [])
            total = len(results)
            clicked = sum(1 for r in results if r.get("status") in ("Clicked Link", "Submitted Data"))
            submitted = sum(1 for r in results if r.get("status") == "Submitted Data")

            status = c.get("status", "Unknown")
            status_color = "green" if status == "Completed" else "yellow" if status == "In progress" else "dim"

            table.add_row(
                str(c.get("id", "?")),
                c.get("name", "Unknown"),
                f"[{status_color}]{status}[/{status_color}]",
                str(total),
                str(clicked),
                str(submitted),
                str(c.get("created_date", ""))[:10],
            )

        console.print(table)

    # ═══════════════════════════════════════════════════════════════════════
    # QUICK TEMPLATES — قوالب جاهزة
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def get_builtin_templates():
        """
        قوالب تصيّد جاهزة — للبدء السريع.
        يمكن تعديلها قبل الاستخدام.
        """
        return {
            "password_reset": {
                "name": "Password Reset Alert",
                "subject": "Urgent: Your password will expire in 24 hours",
                "html": """<html><body>
                    <p>Dear {{.FirstName}},</p>
                    <p>Your corporate password will expire in <b>24 hours</b>.</p>
                    <p>To avoid losing access, please reset your password immediately:</p>
                    <p><a href="{{.URL}}">Reset Password Now</a></p>
                    <p>IT Security Team</p>
                    </body></html>""",
            },
            "shared_document": {
                "name": "Shared Document Notification",
                "subject": "{{.From}} shared a document with you",
                "html": """<html><body>
                    <p>Hi {{.FirstName}},</p>
                    <p>A document has been shared with you via the company portal.</p>
                    <p><a href="{{.URL}}">View Document</a></p>
                    <p>This link will expire in 48 hours.</p>
                    </body></html>""",
            },
            "invoice_payment": {
                "name": "Invoice Payment Required",
                "subject": "Invoice #INV-2026-{{.Position}} - Payment Overdue",
                "html": """<html><body>
                    <p>Dear {{.FirstName}} {{.LastName}},</p>
                    <p>We noticed that invoice #INV-2026-{{.Position}} remains unpaid.</p>
                    <p>Please review and process the payment:</p>
                    <p><a href="{{.URL}}">View Invoice Details</a></p>
                    <p>Finance Department</p>
                    </body></html>""",
            },
            "security_alert": {
                "name": "Suspicious Login Alert",
                "subject": "Alert: Unusual login detected on your account",
                "html": """<html><body>
                    <p>Dear {{.FirstName}},</p>
                    <p>We detected a login to your account from an unrecognized device:</p>
                    <ul>
                        <li>Location: Moscow, Russia</li>
                        <li>Device: Unknown Linux</li>
                        <li>Time: Today at 3:42 AM</li>
                    </ul>
                    <p>If this wasn't you, secure your account immediately:</p>
                    <p><a href="{{.URL}}">Verify My Account</a></p>
                    <p>Security Operations Center</p>
                    </body></html>""",
            },
        }
