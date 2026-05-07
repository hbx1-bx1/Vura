"""
VURA Desktop GUI — Backward-Compatible Entry Point
═══════════════════════════════════════════════════════════
This file preserves the old `gui.py` entry point for backward compatibility.
All logic has been moved to the modular `gui/` package:

    gui/
    ├── main.py          ← App bootstrap + NavigationRail routing
    ├── theme.py         ← Dark theme colors & typography
    ├── i18n.py          ← Translation engine (EN/AR)
    ├── components/      ← Reusable UI building blocks
    ├── engine/          ← Ghost/HookAll hybrid engine
    └── pages/           ← Page builders (home, monitor, analyze...)

Usage:
    python run_gui.py          # Launch GUI
    flet run gui/main.py       # New path also works
    from gui.main import main; ft.app(main)  # Programmatic
"""

# Force UTF-8 on Windows (fixes emoji crash in legacy terminals)
import sys
if sys.stdout and sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and sys.stderr.encoding != 'utf-8':
    sys.stderr.reconfigure(encoding='utf-8')

# Ensure project root is in path
from pathlib import Path
_ROOT = Path(__file__).parent.absolute()
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Delegate to the new modular GUI
from gui.main import main  # noqa: F401

if __name__ == "__main__":
    import flet as ft
    ft.app(main)
