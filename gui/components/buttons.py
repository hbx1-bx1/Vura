"""
VURA GUI — Button Component
═══════════════════════════════════
Reusable styled buttons with icon support.
"""

from __future__ import annotations

from typing import Optional, Callable

import flet as ft

from gui.theme import C, BUTTON_RADIUS, BUTTON_HEIGHT, BTN_PADDING_H, BTN_PADDING_V, BODY_SIZE


def btn(
    label: str,
    icon: Optional[ft.Icons] = None,
    on_click: Optional[Callable] = None,
    color: Optional[str] = None,
    width: Optional[int] = None,
) -> ft.Container:
    """
    Create a styled action button.

    Parameters:
        label: Button text
        icon: Flet icon constant (optional)
        on_click: Click handler
        color: Background color (defaults to primary teal C.T)
        width: Fixed width (optional)

    Returns:
        ft.Container styled as a button
    """
    bg = color or C.T
    row_items: list[ft.Control] = []
    if icon:
        row_items.append(ft.Icon(icon, color=C.W, size=18))
    row_items.append(ft.Text(label, size=BODY_SIZE, color=C.W, weight=ft.FontWeight.W_600))

    return ft.Container(
        content=ft.Row(row_items, spacing=8, alignment=ft.MainAxisAlignment.CENTER),
        bgcolor=bg,
        border_radius=BUTTON_RADIUS,
        padding=ft.Padding.symmetric(horizontal=BTN_PADDING_H, vertical=BTN_PADDING_V),
        width=width,
        height=BUTTON_HEIGHT,
        on_click=on_click,
    )
