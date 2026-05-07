"""
VURA Plugins — Extensible Security Tool Framework
═══════════════════════════════════════════════════
Plugins allow adding new security tools without modifying core code.

Usage:
    from app.plugins import registry

    # Auto-discover plugins
    registry.discover()

    # List available
    for name, plugin in registry.list_available().items():
        print(f"{name}: {plugin.description}")

    # Run a plugin
    nmap = registry.get("nmap")
    result = nmap.execute("example.com")
"""

from .base import (
    VuraPlugin,
    PluginRegistry,
    PluginResult,
    PluginFinding,
    PluginCategory,
    PluginSeverity,
    registry,
)

__all__ = [
    "VuraPlugin",
    "PluginRegistry",
    "PluginResult",
    "PluginFinding",
    "PluginCategory",
    "PluginSeverity",
    "registry",
]
