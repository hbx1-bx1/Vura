"""
VURA GUI — Settings Page
═══════════════════════════════════
Configuration: AI provider, API keys, Telegram, integrations.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import flet as ft

from gui.pages.base import BasePage, AppState
from gui.theme import C
from gui.components.buttons import btn
from gui.components.cards import card, section_header


class SettingsPage(BasePage):
    """Settings and configuration page."""

    def __init__(self, state: AppState, page: ft.Page):
        super().__init__(state, page)
        self._pd: Optional[ft.Dropdown] = None
        self._ak: Optional[ft.TextField] = None
        self._mn: Optional[ft.TextField] = None
        self._bu: Optional[ft.TextField] = None
        self._tt: Optional[ft.TextField] = None
        self._tc: Optional[ft.TextField] = None
        self._sk: Optional[ft.TextField] = None
        self._svs: Optional[ft.Text] = None
        self._enc_status: Optional[ft.Row] = None
        self._enc_icon: Optional[ft.Icon] = None
        self._enc_label: Optional[ft.Text] = None
        self._enc_detail: Optional[ft.Text] = None
        self._cfg: dict = {}
        self._encrypted_keys: dict[str, bool] = {}

    def build(self) -> ft.Control:
        self._load_config()
        self._check_encryption()

        self._pd = self._dd(self.t("prov"), [
            "openai", "openrouter", "anthropic", "deepseek", "qwen", "gemini",
            "groq", "mistral", "together", "venice", "github", "custom",
        ], self._cfg.get("provider", ""), 250)

        self._ak = self._tf(self.t("akey"), self._cfg.get("api_key", ""),
                            400, password=True)
        self._mn = self._tf(self.t("mname"), self._cfg.get("model_name", ""), 300)
        self._bu = self._tf(self.t("curl"), self._cfg.get("base_url", ""), 400)
        self._tt = self._tf(self.t("tgt"), self._cfg.get("tg_bot_token", ""),
                            400, password=True)
        self._tc = self._tf(self.t("tgc"), self._cfg.get("tg_chat_id", ""), 200)
        self._sk = self._tf(self.t("shk"), self._cfg.get("shodan_api_key", ""),
                            400, password=True)
        self._svs = ft.Text("", size=13)

        # Encryption status indicators
        self._enc_icon = ft.Icon(
            ft.Icons.LOCK_OUTLINE if self._encrypted_keys.get("active")
            else ft.Icons.LOCK_OPEN,
            color=C.G if self._encrypted_keys.get("active") else C.O,
            size=20,
        )
        self._enc_label = ft.Text(
            "Encryption Active" if self._encrypted_keys.get("active")
            else "Encryption Inactive",
            size=13,
            weight=ft.FontWeight.BOLD,
            color=C.G if self._encrypted_keys.get("active") else C.O,
        )
        self._enc_detail = ft.Text(
            self._encrypted_keys.get("detail", ""),
            size=11,
            color=C.DM,
        )

        self._enc_status = ft.Row([
            self._enc_icon,
            ft.Column([self._enc_label, self._enc_detail], spacing=2),
        ], spacing=10)

        # Language toggle button
        def on_lang_toggle(e):
            self.state.lang.toggle()
            self._rebuild_nav()
            self._reload()

        lang_toggle = ft.Container(
            content=ft.Row([
                ft.Icon(ft.Icons.TRANSLATE, color=C.W, size=18),
                ft.Text(self.state.lang.display_name(), size=14,
                        color=C.W, weight=ft.FontWeight.BOLD),
            ], spacing=8, alignment=ft.MainAxisAlignment.CENTER),
            bgcolor=C.T2, border_radius=8,
            padding=ft.Padding.symmetric(horizontal=16, vertical=10),
            width=180, height=46,
            on_click=on_lang_toggle,
        )

        def on_save(e):
            try:
                from app.utils.config import save_api_config
                save_api_config({
                    "provider": self._pd.value or "",
                    "api_key": self._ak.value or "",
                    "model_name": self._mn.value or "",
                    "base_url": self._bu.value or "",
                    "tg_bot_token": self._tt.value or "",
                    "tg_chat_id": self._tc.value or "",
                    "shodan_api_key": self._sk.value or "",
                    "gophish_api_key": self._cfg.get("gophish_api_key", ""),
                    "gophish_url": self._cfg.get("gophish_url",
                                                  "https://localhost:3333"),
                })
                self._svs.value = f"\u2714 {self.t('saved')}"
                self._svs.color = C.G
                self._snack(self.t("saved"), C.G)
                self._check_encryption()
                self._refresh_enc_display()
            except Exception as ex:
                self._svs.value = f"Error: {ex}"
                self._svs.color = C.R
            self.page.update()

        return ft.Column([
            section_header(self.t("stitle"), ft.Icons.SETTINGS),
            ft.Container(height=6),
            card([self._enc_status], title="Config Security"),
            ft.Container(height=8),
            card([
                ft.Text(self.t("uilang"), size=15, weight=ft.FontWeight.BOLD, color=C.T),
                ft.Container(height=6),
                ft.Row([lang_toggle, ft.Text("EN \u2194 AR", size=13, color=C.DM)],
                       spacing=12),
            ], title=self.t("uilang")),
            ft.Container(height=8),
            card([self._pd, self._ak, self._mn, self._bu], title=self.t("ai")),
            ft.Container(height=8),
            card([self._tt, self._tc], title=self.t("tgn")),
            ft.Container(height=8),
            card([self._sk], title=self.t("integ")),
            ft.Container(height=12),
            ft.Row([btn(self.t("save"), ft.Icons.SAVE, on_save, C.T, 220),
                    self._svs], spacing=12),
        ], scroll=ft.ScrollMode.AUTO, spacing=8)

    def _load_config(self):
        """Load current configuration."""
        try:
            from app.utils.config import load_api_config
            self._cfg = load_api_config() or {}
        except Exception:
            self._cfg = {}

    def _check_encryption(self):
        """Check encryption status of config keys."""
        try:
            from app.utils.crypto import KeyVault, SENSITIVE_KEYS, ENCRYPTED_PREFIX
            vault = KeyVault.instance()

            key_path = vault.get_key_path()
            key_exists = vault.key_exists()

            encrypted_count = 0
            plain_count = 0
            for key in SENSITIVE_KEYS:
                val = self._cfg.get(key, "")
                if val:
                    if str(val).startswith(ENCRYPTED_PREFIX):
                        encrypted_count += 1
                    else:
                        plain_count += 1

            has_sensitive = encrypted_count > 0 or plain_count > 0
            active = has_sensitive and encrypted_count > 0 and plain_count == 0

            self._encrypted_keys = {
                "active": active,
                "key_exists": key_exists,
                "key_path": str(key_path),
                "encrypted_count": encrypted_count,
                "plain_count": plain_count,
                "detail": self._build_enc_detail(active, key_exists,
                                                 encrypted_count, plain_count),
            }
        except ImportError:
            self._encrypted_keys = {
                "active": False,
                "key_exists": False,
                "detail": "cryptography library not installed",
            }
        except Exception as e:
            self._encrypted_keys = {
                "active": False,
                "key_exists": False,
                "detail": f"Error: {e}",
            }

    def _build_enc_detail(self, active: bool, key_exists: bool,
                          encrypted: int, plain: int) -> str:
        """Build encryption status detail string."""
        parts = []
        if key_exists:
            parts.append("Master key present")
        else:
            parts.append("No master key")

        total = encrypted + plain
        if total > 0:
            parts.append(f"{encrypted}/{total} keys encrypted")
            if plain > 0:
                parts.append(f"{plain} keys in plaintext")
        else:
            parts.append("No sensitive keys set")

        return "  \u2022  ".join(parts)

    def _refresh_enc_display(self):
        """Update encryption status UI after save."""
        if not self._enc_icon or not self._enc_label or not self._enc_detail:
            return

        active = self._encrypted_keys.get("active", False)
        self._enc_icon.name = ft.Icons.LOCK_OUTLINE if active else ft.Icons.LOCK_OPEN
        self._enc_icon.color = C.G if active else C.O
        self._enc_label.value = "Encryption Active" if active else "Encryption Inactive"
        self._enc_label.color = C.G if active else C.O
        self._enc_detail.value = self._encrypted_keys.get("detail", "")

    def _rebuild_nav(self):
        """Trigger navigation rail label rebuild — set by main.py."""
        if hasattr(self, '_rebuild_nav_callback'):
            self._rebuild_nav_callback()

    def _reload(self):
        """Rebuild the page with new language."""
        if hasattr(self, '_reload_callback'):
            self._reload_callback()

    def _snack(self, msg: str, color=None):
        if hasattr(self, '_show_snack'):
            self._show_snack(msg, color)
