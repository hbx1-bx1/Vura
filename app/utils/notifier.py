"""
VURA Notifier — Telegram Alerts & Notifications
════════════════════════════════════════════════
Sends scan results, alerts, and reports via Telegram.
Supports text messages, PDF file uploads, and severity-based alerts.
"""

import os
from pathlib import Path

import requests
from app.utils.config import load_api_config
from rich.console import Console

console = Console()


def escape_telegram_markdown(text: str) -> str:
    """
    ✅ FIX #8 — تهريب كامل لجميع رموز Telegram MarkdownV1.

    الرموز الخاصة في MarkdownV1:
    _  *  `  [  ]  (  )  ~  >  #  +  -  =  |  {  }  .  !  \\
    """
    if not text:
        return ""
    # ✅ يجب هروب الـ backslash أولاً قبل أي رمز آخر
    special_chars = ["\\", "_", "*", "`", "[", "]", "(", ")", "~", ">",
                     "#", "+", "-", "=", "|", "{", "}", ".", "!"]
    for char in special_chars:
        text = text.replace(char, f"\\{char}")
    return text


def _get_telegram_config():
    """تحميل إعدادات Telegram من config."""
    config = load_api_config()
    if not config:
        return None, None

    bot_token = config.get("tg_bot_token", "").strip()
    chat_id   = config.get("tg_chat_id", "").strip()

    if not bot_token or not chat_id:
        return None, None

    return bot_token, chat_id


def send_telegram_alert(report_path: str, summary_data: str = None, mode: str = "short"):
    """
    إرسال إشعار Telegram.

    Parameters:
        report_path  : مسار التقرير
        summary_data : ملخص التقرير (للـ long mode)
        mode         : "short" = رسالة قصيرة, "long" = مع ملخص
    """
    bot_token, chat_id = _get_telegram_config()
    if not bot_token:
        return

    safe_path = escape_telegram_markdown(report_path)

    if mode == "short":
        text = f"*VURA Engine:* Scan Completed\\!\n*Report:* `{safe_path}`"
    else:
        safe_summary = escape_telegram_markdown(
            summary_data[:1500] + "..." if summary_data and len(summary_data) > 1500
            else summary_data or "N/A"
        )
        text = (
            f"*VURA Security Alert*\n\n"
            f"*Status:* Analysis Completed\n"
            f"*Report:* `{safe_path}`\n\n"
            f"*Summary:*\n```\n{safe_summary}\n```"
        )

    _send_message(bot_token, chat_id, text)


def send_telegram_file(file_path: str, caption: str = ""):
    """
    إرسال ملف (PDF/TXT) عبر Telegram.

    Parameters:
        file_path : مسار الملف
        caption   : عنوان الملف
    """
    bot_token, chat_id = _get_telegram_config()
    if not bot_token:
        return False

    if not os.path.exists(file_path):
        console.print(f"[dim red][!] Telegram: File not found: {file_path}[/dim red]")
        return False

    url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
    try:
        with open(file_path, "rb") as f:
            response = requests.post(
                url,
                data={"chat_id": chat_id, "caption": caption[:1024]},
                files={"document": (os.path.basename(file_path), f)},
                timeout=30,
            )
        if response.status_code != 200:
            console.print(f"[dim red][!] Telegram file send failed: {response.text[:100]}[/dim red]")
            return False
        return True
    except requests.exceptions.RequestException as e:
        console.print(f"[dim red][!] Telegram file send error: {e}[/dim red]")
        return False


def send_severity_alert(target: str, critical: int = 0, high: int = 0,
                         medium: int = 0, low: int = 0, report_path: str = ""):
    """
    إشعار مُلوَّن حسب الخطورة — يُرسل بعد كل فحص.

    Parameters:
        target       : الهدف المفحوص
        critical/high/medium/low : عدد الثغرات لكل مستوى
        report_path  : مسار التقرير
    """
    bot_token, chat_id = _get_telegram_config()
    if not bot_token:
        return

    total = critical + high + medium + low
    safe_target = escape_telegram_markdown(target)

    if critical > 0:
        severity_icon = "🔴"
        severity_text = "CRITICAL"
    elif high > 0:
        severity_icon = "🟠"
        severity_text = "HIGH"
    elif medium > 0:
        severity_icon = "🟡"
        severity_text = "MEDIUM"
    elif low > 0:
        severity_icon = "🟢"
        severity_text = "LOW"
    else:
        severity_icon = "✅"
        severity_text = "CLEAN"

    text = (
        f"{severity_icon} *VURA Scan Alert — {severity_text}*\n\n"
        f"*Target:* `{safe_target}`\n"
        f"*Findings:* {total} total\n"
    )

    if total > 0:
        text += (
            f"  🔴 Critical: {critical}\n"
            f"  🟠 High: {high}\n"
            f"  🟡 Medium: {medium}\n"
            f"  🟢 Low: {low}\n"
        )

    if report_path:
        safe_path = escape_telegram_markdown(report_path)
        text += f"\n*Report:* `{safe_path}`"

    _send_message(bot_token, chat_id, text)


def _send_message(bot_token: str, chat_id: str, text: str):
    """إرسال رسالة Telegram — helper موحّد."""
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        response = requests.post(
            url,
            json={"chat_id": chat_id, "text": text, "parse_mode": "MarkdownV2"},
            timeout=10,
        )
        if response.status_code != 200:
            console.print(f"[dim red][!] Telegram alert failed: {response.text[:100]}[/dim red]")
    except requests.exceptions.RequestException as e:
        console.print(f"[dim red][!] Telegram connection error: {e}[/dim red]")
