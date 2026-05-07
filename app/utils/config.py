"""
VURA Configuration Manager — Phase 4 (Encrypted)
══════════════════════════════════════════════════
Reads, writes, and validates config.json with transparent
Fernet encryption for sensitive API keys.

Encryption architecture:
  - Sensitive keys (api_key, tg_bot_token, shodan_api_key, etc.)
    are encrypted before saving to config.json
  - Decrypted automatically on load for internal use
  - Master key stored separately in data/.vura_master.key
  - File permissions: chmod 0o600 (owner-only)
"""

import json
import os
import sys
import copy
import subprocess
from typing import Optional

# ── Paths ────────────────────────────────────────────────────────────
from pathlib import Path as _Path
_PROJECT_ROOT = _Path(__file__).parent.parent.parent.absolute()
CONFIG_FILE   = _PROJECT_ROOT / "config.json"

_IS_WINDOWS = sys.platform.startswith("win")

# ── Lazy import crypto (graceful fallback if cryptography not installed) ─
_crypto_available = False
try:
    from app.utils.crypto import (
        encrypt_config, decrypt_config,
        is_encrypted, get_vault, KeyVault,
    )
    _crypto_available = True
except Exception:
    _crypto_available = False


def _restrict_permissions(path: _Path) -> None:
    """
    Restrict a file so only the current user can read it.
    POSIX: chmod 0o600. Windows: icacls ACL.
    """
    if not _IS_WINDOWS:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return

    user = os.environ.get("USERNAME") or ""
    if not user:
        _warn_once_windows_perms(path)
        return

    try:
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
        f'    icacls "{path}" /inheritance:r /grant:r "%USERNAME%:F"',
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
    "gemini", "groq", "mistral", "together", "venice", "github",
    "huggingface", "custom",
]


def save_api_config(config_data: dict):
    """
    حفظ الإعدادات مع تشفير تلقائي للمفاتيح الحساسة.

    Sensitive keys are encrypted before writing to disk.
    File permissions restricted to owner-only (0o600).
    """
    # Encrypt sensitive keys before saving
    if _crypto_available:
        config_data = encrypt_config(config_data)

    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=4, ensure_ascii=False)
    _restrict_permissions(CONFIG_FILE)


def load_api_config() -> Optional[dict]:
    """
    تحميل الإعدادات مع فك تشفير تلقائي للمفاتيح الحساسة.

    Creates config.json with defaults if missing.
    Decrypts encrypted values transparently.
    """
    if not os.path.exists(CONFIG_FILE):
        save_api_config(copy.deepcopy(DEFAULT_CONFIG))

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            raw_config = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    # Decrypt sensitive keys
    if _crypto_available:
        return decrypt_config(raw_config)

    return raw_config


def load_api_config_raw() -> Optional[dict]:
    """
    Load config without decryption — returns raw values from disk.
    Useful for checking if values are encrypted.
    """
    if not os.path.exists(CONFIG_FILE):
        return None
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
        errors.append(
            f"Unknown provider '{provider}'. "
            f"Supported: {', '.join(SUPPORTED_PROVIDERS)}"
        )

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


def get_encryption_status() -> dict:
    """
    Return encryption status for diagnostics.

    Returns:
        dict with crypto_available, master_key_exists, encrypted_keys info
    """
    status = {
        "crypto_available": _crypto_available,
        "master_key_exists": False,
        "master_key_path": "",
        "encrypted_keys": [],
        "plaintext_keys": [],
    }

    if not _crypto_available:
        return status

    try:
        vault = get_vault()
        status["master_key_exists"] = vault.key_exists()
        status["master_key_path"] = str(vault.get_key_path())

        raw_config = load_api_config_raw() or {}
        sensitive_keys = {
            "api_key", "shodan_api_key",
            "tg_bot_token", "gophish_api_key",
        }
        for key in sensitive_keys:
            value = raw_config.get(key, "")
            if value:
                if is_encrypted(value):
                    status["encrypted_keys"].append(key)
                else:
                    status["plaintext_keys"].append(key)
    except Exception:
        pass

    return status


def migrate_to_encrypted() -> bool:
    """
    Migrate existing plaintext keys to encrypted format.

    Returns:
        True if migration succeeded, False if already encrypted or no keys to migrate
    """
    if not _crypto_available:
        return False

    raw_config = load_api_config_raw()
    if not raw_config:
        return False

    sensitive_keys = {
        "api_key", "shodan_api_key",
        "tg_bot_token", "gophish_api_key",
    }
    migrated = False

    for key in sensitive_keys:
        value = raw_config.get(key, "")
        if value and not is_encrypted(value):
            raw_config[key] = encrypt_config({key: value})[key]
            migrated = True

    if migrated:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(raw_config, f, indent=4, ensure_ascii=False)
        _restrict_permissions(CONFIG_FILE)

    return migrated
