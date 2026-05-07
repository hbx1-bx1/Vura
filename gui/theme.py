"""
VURA GUI — Theme
═══════════════════════════════════
Dark theme color palette, typography constants, and shared visual styling.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class VuraColors:
    """Dark theme color palette."""
    T: str = "#1abc9c"    # Teal primary
    T2: str = "#16a085"   # Teal dark
    N: str = "#1a1a2e"    # Background dark
    N2: str = "#22223a"   # Card background
    N3: str = "#2a2a4a"   # Border / separator
    S: str = "#16213e"    # Surface
    S2: str = "#1e2d50"   # Surface light
    CD: str = "#0f3460"   # Card dark blue
    DM: str = "#8899aa"   # Dim text
    R: str = "#e74c3c"    # Red (error)
    O: str = "#f39c12"    # Orange (warning)
    G: str = "#2ecc71"    # Green (success)
    Y: str = "#f1c40f"    # Yellow
    W: str = "#ffffff"    # White text
    BG: str = "#0a0a1a"   # Page background


C = VuraColors()

# ── Typography ───────────────────────────────────────────────────────
TITLE_SIZE = 18
SUBTITLE_SIZE = 14
BODY_SIZE = 13
SMALL_SIZE = 12
TINY_SIZE = 10

# ── Spacing & Sizing ─────────────────────────────────────────────────
CARD_RADIUS = 12
CARD_PADDING = 20
BUTTON_RADIUS = 8
BUTTON_HEIGHT = 42
BTN_PADDING_H = 16
BTN_PADDING_V = 10

# ── Window Defaults ──────────────────────────────────────────────────
WIN_WIDTH = 1200
WIN_HEIGHT = 800
WIN_MIN_WIDTH = 900
WIN_MIN_HEIGHT = 600
