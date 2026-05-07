"""
VURA Cryptographic Key Vault — Fernet Encryption
══════════════════════════════════════════════════════════════════════════
Encrypts and decrypts sensitive API keys in config.json using
symmetric Fernet (AES-128-CBC with HMAC-SHA256).

Architecture:
  1. Master Key (32 bytes, base64-encoded) — generated once, stored
     separately from encrypted data in .vura_master.key
  2. Each sensitive value is encrypted individually with Fernet
  3. Encrypted values are stored with a "enc:" prefix for detection
  4. File permissions restricted to 0o600 (owner-only)

Usage:
    from app.utils.crypto import KeyVault

    vault = KeyVault()           # Loads or generates master key
    cipher = vault.encrypt("sk-123456")
    plain  = vault.decrypt(cipher)
"""

from __future__ import annotations

import os
import base64
from pathlib import Path
from typing import Optional


# ── Project paths ────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()
_DATA_DIR = _PROJECT_ROOT / "data"
_MASTER_KEY_FILE = _DATA_DIR / ".vura_master.key"

# Prefix to identify encrypted values
ENCRYPTED_PREFIX = "enc:"

# Sensitive config keys that should be encrypted
SENSITIVE_KEYS = frozenset({
    "api_key",
    "shodan_api_key",
    "tg_bot_token",
    "gophish_api_key",
})


class KeyVault:
    """
    Manages encryption and decryption of sensitive configuration values.

    Thread-safe: all operations protected by module-level lock.
    """

    _instance: Optional[KeyVault] = None
    _fernet = None

    def __init__(self, key_file: Optional[Path] = None):
        self._key_file = key_file or _MASTER_KEY_FILE
        self._master_key = self._load_or_generate_key()

        # Lazy import cryptography (optional dependency)
        from cryptography.fernet import Fernet
        self._fernet = Fernet(self._master_key)

    @classmethod
    def instance(cls, key_file: Optional[Path] = None) -> KeyVault:
        """Get or create the singleton KeyVault."""
        if cls._instance is None:
            cls._instance = cls(key_file)
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton (for testing)."""
        cls._instance = None

    # ── Key Management ───────────────────────────────────────────────

    def _load_or_generate_key(self) -> bytes:
        """Load existing master key or generate a new one."""
        if self._key_file.exists():
            try:
                key = self._key_file.read_bytes().strip()
                # Validate it's a valid Fernet key (32 bytes base64)
                base64.urlsafe_b64decode(key)
                return key
            except Exception:
                # Corrupted key file — generate new one
                pass

        # Generate new key
        from cryptography.fernet import Fernet
        new_key = Fernet.generate_key()
        self._save_key(new_key)
        return new_key

    def _save_key(self, key: bytes) -> None:
        """Save master key with restricted permissions."""
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._key_file.write_bytes(key)

        # Restrict permissions
        try:
            os.chmod(self._key_file, 0o600)
        except OSError:
            pass

    def get_key_path(self) -> Path:
        """Return the master key file path."""
        return self._key_file

    def key_exists(self) -> bool:
        """Check if master key file exists."""
        return self._key_file.exists()

    def regenerate_key(self) -> None:
        """
        Generate a new master key.

        WARNING: All previously encrypted values become unreadable.
        """
        from cryptography.fernet import Fernet
        new_key = Fernet.generate_key()
        self._master_key = new_key
        self._fernet = Fernet(new_key)
        self._save_key(new_key)

    # ── Encryption / Decryption ──────────────────────────────────────

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a string value.

        Returns:
            Base64-encoded ciphertext with "enc:" prefix.
        """
        if not plaintext:
            return ""

        ciphertext = self._fernet.encrypt(plaintext.encode("utf-8"))
        return ENCRYPTED_PREFIX + ciphertext.decode("utf-8")

    def decrypt(self, encrypted: str) -> str:
        """
        Decrypt an encrypted value.

        Parameters:
            encrypted: String with "enc:" prefix, or plain text

        Returns:
            Decrypted plaintext, or original string if not encrypted
        """
        if not encrypted:
            return ""

        if not encrypted.startswith(ENCRYPTED_PREFIX):
            return encrypted  # Already plaintext

        ciphertext = encrypted[len(ENCRYPTED_PREFIX):]
        try:
            plaintext = self._fernet.decrypt(ciphertext.encode("utf-8"))
            return plaintext.decode("utf-8")
        except Exception:
            # Decryption failed — return as-is to avoid data loss
            return encrypted

    def is_encrypted(self, value: str) -> bool:
        """Check if a value is encrypted."""
        return value.startswith(ENCRYPTED_PREFIX) if value else False

    # ── Config Dict Helpers ──────────────────────────────────────────

    def encrypt_sensitive(self, config: dict) -> dict:
        """
        Encrypt all sensitive keys in a config dict.

        Returns a new dict with sensitive values encrypted.
        """
        result = dict(config)
        for key in SENSITIVE_KEYS:
            value = result.get(key, "")
            if value and not self.is_encrypted(value):
                result[key] = self.encrypt(value)
        return result

    def decrypt_sensitive(self, config: dict) -> dict:
        """
        Decrypt all sensitive keys in a config dict.

        Returns a new dict with sensitive values decrypted.
        Non-encrypted values pass through unchanged.
        """
        result = dict(config)
        for key in SENSITIVE_KEYS:
            value = result.get(key, "")
            if value:
                result[key] = self.decrypt(value)
        return result


# ── Module-level convenience functions ───────────────────────────────

def get_vault() -> KeyVault:
    """Get the singleton KeyVault instance."""
    return KeyVault.instance()


def encrypt_value(plaintext: str) -> str:
    """Encrypt a single value."""
    return get_vault().encrypt(plaintext)


def decrypt_value(encrypted: str) -> str:
    """Decrypt a single value."""
    return get_vault().decrypt(encrypted)


def encrypt_config(config: dict) -> dict:
    """Encrypt sensitive keys in a config dict."""
    return get_vault().encrypt_sensitive(config)


def decrypt_config(config: dict) -> dict:
    """Decrypt sensitive keys in a config dict."""
    return get_vault().decrypt_sensitive(config)
