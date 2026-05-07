"""
VURA GUI — Card & Section Header Components
══════════════════════════════════════════════
Reusable card containers and section headers.
"""

from __future__ import annotations

from typing import Optional, Union, List

import flet as ft

from gui.theme import C, CARD_RADIUS, CARD_PADDING, TITLE_SIZE


def card(
    content: Union[List[ft.Control], ft.Control],
    title: Optional[str] = None,
    width: Optional[int] = None,
) -> ft.Container:
    """
    Create a dark-themed card container with optional title.

    Parameters:
        content: Single control or list of controls
        title: Optional bold header text
        width: Fixed width (optional)

    Returns:
        ft.Container with dark background, rounded borders
    """
    children: list[ft.Control] = []
    if title:
        children.append(ft.Text(title, size=14, weight=ft.FontWeight.BOLD, color=C.T))
        children.append(ft.Divider(height=1, color=C.N3))

    if isinstance(content, list):
        children.extend(content)
    else:
        children.append(content)

    return ft.Container(
        content=ft.Column(children, spacing=10),
        bgcolor=C.N2,
        border_radius=CARD_RADIUS,
        padding=CARD_PADDING,
        width=width,
        border=ft.Border.all(1, C.N3),
    )


def section_header(text: str, icon: Optional[ft.Icons] = None) -> ft.Row:
    """
    Create a section header row with optional icon.

    Parameters:
        text: Section title
        icon: Optional leading icon

    Returns:
        ft.Row with icon + bold title
    """
    items: list[ft.Control] = []
    if icon:
        items.append(ft.Icon(icon, color=C.T, size=20))
    items.append(ft.Text(text, size=TITLE_SIZE, weight=ft.FontWeight.BOLD, color=C.W))
    return ft.Row(items, spacing=8)
