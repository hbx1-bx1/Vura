"""
VURA Configuration Manager
═══════════════════════════
Reads, writes, and validates config.json.
Single source of truth for all configuration access.
"""

import json
import os
import sys
import copy
import subprocess
from typing import Optional

# ✅ FIX #4 — مسار مطلق: يعمل من أي مجلد تشغّل منه الأداة
from pathlib import Path as _Path
_PROJECT_ROOT = _Path(__file__).parent.parent.parent.absolute()
CONFIG_FILE   = _PROJECT_ROOT / "config.json"

_IS_WINDOWS = sys.platform.startswith("win")


def _restrict_permissions(path: _Path) -> None:
    """
    Restrict a file so only the current user can read it.

    POSIX: chmod 0o600 (owner rw, no group/other access).
    Windows: chmod's POSIX bits are effectively a no-op. We try icacls to
    grant FullControl to the current user and strip Users/Authenticated Users.
    If icacls is unavailable (stripped Windows image, permission denied) we
    fall back to a one-time console warning so the user knows the file is
    world-readable by default.
    """
    if not _IS_WINDOWS:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return

    # Windows: POSIX bits don't apply. Use icacls for real ACL-level protection.
    user = os.environ.get("USERNAME") or ""
    if not user:
        _warn_once_windows_perms(path)
        return

    try:
        # /inheritance:r  — remove inherited ACEs
        # /grant:r        — replace existing grants for the named principal
        # /remove         — strip the specified group entirely
        subprocess.run(
            ["icacls", str(path), "/inheritance:r",
             "/grant:r", f"{user}:F",
             "/remove", "Users", "/remove", "Authenticated Users"],
            check=False, capture_output=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        _warn_once_windows_perms(path)


_warned_perms = False
def _warn_once_windows_perms(path: _Path) -> None:
    global _warned_perms
    if _warned_perms:
        return
    _warned_perms = True
    print(
        f"[!] VURA: could not restrict ACL on {path} (Windows). "
        "The file may be readable by other local users. "
        "Consider moving the repo to a user-only directory or setting "
        "permissions manually with:\n"
        f"    icacls \"{path}\" /inheritance:r /grant:r \"%USERNAME%:F\"",
        file=sys.stderr,
    )

# ─── Default Config Template ────────────────────────────────────────
DEFAULT_CONFIG = {
    "provider":              "gemini",
    "api_key":               "",
    "model_name":            "gemini-2.0-flash",
    "base_url":              "",
    "tg_bot_token":          "",
    "tg_chat_id":            "",
    "shodan_api_key":        "",
    "gophish_api_key":       "",
    "gophish_url":           "https://localhost:3333",
}

# ─── Supported Providers ─────────────────────────────────────────────
SUPPORTED_PROVIDERS = [
    "openai", "openrouter", "anthropic", "deepseek", "qwen",
    "gemini", "groq", "mistral", "together", "venice", "github", "custom",
]


def save_api_config(config_data: dict):
    """حفظ الإعدادات مع حماية ACL على كلا النظامين (POSIX chmod + Windows icacls)."""
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=4, ensure_ascii=False)
    _restrict_permissions(CONFIG_FILE)


def load_api_config() -> Optional[dict]:
    """تحميل الإعدادات — ينشئ config.json بالقيم الافتراضية تلقائياً إذا لم يكن موجوداً."""
    if not os.path.exists(CONFIG_FILE):
        save_api_config(copy.deepcopy(DEFAULT_CONFIG))
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def get_config_value(key: str, default=None):
    """جلب قيمة واحدة من الإعدادات."""
    config = load_api_config()
    if config:
        return config.get(key, default)
    return default


def update_config(updates: dict):
    """تحديث حقول محددة بدون مسح الباقي."""
    config = load_api_config() or {}
    config.update(updates)
    save_api_config(config)


def ensure_config_exists():
    """إنشاء config.json بالقيم الافتراضية إذا لم يكن موجوداً."""
    if not os.path.exists(CONFIG_FILE):
        save_api_config(copy.deepcopy(DEFAULT_CONFIG))
        return True
    return False


def validate_config() -> list:
    """
    فحص صحة الإعدادات.
    يرجع قائمة أخطاء (فارغة = كل شيء صحيح).
    """
    config = load_api_config()
    errors = []

    if not config:
        return ["config.json is missing or corrupted. Run: vura -Ch"]

    if not (config.get("provider") or "").strip():
        errors.append("No 'provider' set. Run: vura -Ch")

    if not (config.get("api_key") or "").strip():
        errors.append("No 'api_key' set. Run: vura -Ch")

    provider = (config.get("provider") or "").strip().lower()
    if provider and provider not in SUPPORTED_PROVIDERS:
        errors.append(f"Unknown provider '{provider}'. Supported: {', '.join(SUPPORTED_PROVIDERS)}")

    if provider == "custom" and not (config.get("base_url") or "").strip():
        errors.append("provider='custom' requires 'base_url' in config.json")

    return errors


def get_config_summary() -> dict:
    """ملخص الإعدادات — للعرض في diagnostics (بدون كشف المفاتيح)."""
    config = load_api_config() or {}

    def _mask(key_value):
        if not key_value or len(key_value) < 8:
            return "Not set"
        return f"{key_value[:6]}...{key_value[-4:]}"

    return {
        "provider":     config.get("provider", "Not set"),
        "model_name":   config.get("model_name", "Not set"),
        "api_key":      _mask(config.get("api_key", "")),
        "telegram":     "Configured" if config.get("tg_bot_token") else "Not set",
        "shodan":       "Configured" if config.get("shodan_api_key") else "Not set",
        "gophish":      "Configured" if config.get("gophish_api_key") else "Not set",
    }
