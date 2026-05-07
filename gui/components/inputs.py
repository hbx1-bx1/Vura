"""
VURA GUI — Input Components
═══════════════════════════════════
Reusable text fields and dropdowns.
"""

from __future__ import annotations

from typing import Optional, List, Tuple, Union

import flet as ft

from gui.theme import C, BODY_SIZE


def text_field(
    label: str,
    value: str = "",
    width: Optional[int] = None,
    multiline: bool = False,
    password: bool = False,
    icon: Optional[ft.Icons] = None,
    read_only: bool = False,
    lines: int = 6,
) -> ft.TextField:
    """
    Create a styled text field.

    Parameters:
        label: Field label
        value: Initial value
        width: Fixed width (optional)
        multiline: Multi-line text area
        password: Obscured input
        icon: Leading icon
        read_only: Disable editing
        lines: Min lines for multiline

    Returns:
        ft.TextField with dark theme styling
    """
    kw: dict = dict(
        label=label,
        value=value,
        border_color=C.N3,
        focused_border_color=C.T,
        color=C.W,
        label_style=ft.TextStyle(color=C.DM),
        bgcolor=C.N,
    )
    if width:
        kw["width"] = width
    if multiline:
        kw["multiline"] = True
        kw["min_lines"] = lines
        kw["max_lines"] = 100
    if password:
        kw["password"] = True
        kw["can_reveal_password"] = True
    if icon:
        kw["prefix_icon"] = icon
    if read_only:
        kw["read_only"] = True
    return ft.TextField(**kw)


def dropdown(
    label: str,
    options: List[Union[str, Tuple[str, str]]],
    value: str,
    width: int = 180,
) -> ft.Dropdown:
    """
    Create a styled dropdown selector.

    Parameters:
        label: Field label
        options: List of strings or (key, display) tuples
        value: Selected value
        width: Fixed width

    Returns:
        ft.Dropdown with dark theme styling
    """
    opts = [
        ft.dropdown.Option(*o) if isinstance(o, tuple) else ft.dropdown.Option(o)
        for o in options
    ]
    return ft.Dropdown(
        label=label,
        width=width,
        options=opts,
        value=value,
        border_color=C.N3,
        focused_border_color=C.T,
        color=C.W,
        label_style=ft.TextStyle(color=C.DM),
        bgcolor=C.N,
    )
