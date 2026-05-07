"""
VURA GUI — Pages
═══════════════════════════════════
Application pages with navigation routing.
"""

from .base import AppState, BasePage
from .home import HomePage
from .monitor import MonitorPage
from .analyze import AnalyzePage
from .recon import ReconPage
from .reports import ReportsPage
from .settings import SettingsPage

__all__ = [
    "AppState",
    "BasePage",
    "HomePage",
    "MonitorPage",
    "AnalyzePage",
    "ReconPage",
    "ReportsPage",
    "SettingsPage",
]
