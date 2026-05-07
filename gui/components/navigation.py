"""
VURA GUI — Navigation & Utility Components
═══════════════════════════════════════════════
Snack bar, background task runner, and page header helpers.
"""

from __future__ import annotations

import threading
import traceback
from typing import Optional, Callable, Any

import flet as ft

from gui.theme import C


def create_snack_bar() -> tuple[ft.Container, Callable]:
    """
    Create an animated snack bar and return (container, show_callback).

    Returns:
        Tuple of (snack_container, snack_callable)
        snack_callable(msg, color) shows the bar for 3 seconds
    """
    container = ft.Container(
        content=ft.Text("", size=13, color=C.W),
        bgcolor=C.T,
        height=0,
        padding=ft.Padding.symmetric(horizontal=20, vertical=0),
        animate=ft.Animation(300, ft.AnimationCurve.EASE_OUT),
    )

    def show(msg: str, color: Optional[str] = None) -> None:
        container.content = ft.Text(msg, size=13, color=C.W)
        container.bgcolor = color or C.T
        container.height = 42
        container.padding = ft.Padding.symmetric(horizontal=20, vertical=10)
        # page.update() must be called by the caller

        def hide():
            import time
            time.sleep(3)
            container.height = 0
            container.padding = ft.Padding.symmetric(horizontal=20, vertical=0)

        threading.Thread(target=hide, daemon=True).start()

    return container, show


def run_bg(
    page: ft.Page,
    fn: Callable[[], Any],
    cb: Optional[Callable[[Any], None]] = None,
) -> None:
    """
    Run a function in a background thread with safe UI callback.

    Parameters:
        page: Flet page for update
        fn: Function to run in background
        cb: Callback with result (runs on UI thread via page.update)
    """
    def wrapper():
        try:
            result = fn()
            if cb:
                cb(result)
        except Exception as e:
            if cb:
                cb(f"ERROR: {e}\n{traceback.format_exc()}")
        finally:
            try:
                page.update()
            except Exception:
                pass

    threading.Thread(target=wrapper, daemon=True).start()
