"""
VURA Plugin System — Base Interface
═════════════════════════════════════
Abstract base class for VURA plugins.

Plugins allow adding new security tools (Nmap, Nikto, SQLMap, etc.)
without modifying the core codebase.

Usage:
    from app.plugins.base import VuraPlugin, PluginResult, PluginCategory

    class MyNiktoPlugin(VuraPlugin):
        name = "nikto"
        category = PluginCategory.WEB_SCAN

        def check_available(self) -> bool:
            return shutil.which("nikto") is not None

        def execute(self, target, **kwargs) -> PluginResult:
            # Run nikto and return results
            ...
"""

from __future__ import annotations

import enum
import abc
import datetime
from dataclasses import dataclass, field
from typing import Optional, Any


# ══════════════════════════════════════════════════════════════════════
# ENUMS
# ══════════════════════════════════════════════════════════════════════

class PluginCategory(enum.Enum):
    """Categories for security tool plugins."""
    RECON = "recon"               # Discovery / OSINT
    NETWORK_SCAN = "network_scan"  # Port / service scanning
    WEB_SCAN = "web_scan"          # Web application testing
    VULN_SCAN = "vuln_scan"        # Vulnerability assessment
    EXPLOIT = "exploit"            # Exploitation tools
    BRUTE_FORCE = "brute_force"    # Password testing
    COMPLIANCE = "compliance"      # Compliance checking
    CUSTOM = "custom"              # User-defined


class PluginSeverity(enum.Enum):
    """Severity levels for plugin findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ══════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ══════════════════════════════════════════════════════════════════════

@dataclass
class PluginFinding:
    """
    A single security finding from a plugin.

    Attributes:
        title: Short description of the finding
        severity: Severity level
        cve: CVE ID if applicable
        component: Affected service/component
        evidence: Proof/output that triggered this finding
        remediation: How to fix it
        raw_output: Full raw output from the tool
    """
    title: str
    severity: PluginSeverity = PluginSeverity.INFO
    cve: Optional[str] = None
    component: str = ""
    evidence: str = ""
    remediation: str = ""
    raw_output: str = ""


@dataclass
class PluginResult:
    """
    Complete result from a plugin execution.

    Attributes:
        plugin_name: Name of the plugin that produced this result
        target: Target that was scanned/analyzed
        success: Whether the plugin executed successfully
        findings: List of security findings
        raw_output: Full output from the tool
        error: Error message if failed
        duration_seconds: How long the plugin ran
        metadata: Extra plugin-specific data
    """
    plugin_name: str
    target: str
    success: bool = True
    findings: list[PluginFinding] = field(default_factory=list)
    raw_output: str = ""
    error: Optional[str] = None
    duration_seconds: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def summary(self) -> str:
        """Human-readable summary of findings."""
        if not self.findings:
            return f"No findings for {self.target}"

        counts = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        parts = [f"{v} {k}" for k, v in sorted(counts.items())]
        return f"{self.target}: {', '.join(parts)}"


# ══════════════════════════════════════════════════════════════════════
# BASE PLUGIN
# ══════════════════════════════════════════════════════════════════════

class VuraPlugin(abc.ABC):
    """
    Abstract base class for all VURA plugins.

    To create a new plugin:
      1. Subclass VuraPlugin
      2. Set class attributes (name, category, version)
      3. Implement check_available() and execute()
      4. Place the file in app/plugins/
    """

    # ── Class attributes (must be set by subclasses) ───────────────
    name: str = "unnamed"
    category: PluginCategory = PluginCategory.CUSTOM
    version: str = "0.0.0"
    description: str = ""
    author: str = ""
    homepage: str = ""

    # ── Abstract methods ───────────────────────────────────────────

    @abc.abstractmethod
    def check_available(self) -> bool:
        """
        Check if this plugin's tool is installed and usable.

        Returns:
            True if the tool is available, False otherwise.
        """
        ...

    @abc.abstractmethod
    def execute(self, target: str, **kwargs: Any) -> PluginResult:
        """
        Execute the security tool against a target.

        Parameters:
            target: The target (domain, IP, URL, etc.)
            **kwargs: Tool-specific parameters

        Returns:
            PluginResult with findings and raw output.
        """
        ...

    # ── Optional overrides ─────────────────────────────────────────

    def get_default_args(self) -> dict[str, Any]:
        """
        Return default arguments for this plugin's execute method.

        Override to provide sensible defaults.
        """
        return {}

    def get_help(self) -> str:
        """Return a help string describing the plugin's usage."""
        lines = [
            f"Plugin: {self.name} v{self.version}",
            f"Category: {self.category.value}",
            f"Description: {self.description}",
            f"Available: {'Yes' if self.check_available() else 'No'}",
        ]
        defaults = self.get_default_args()
        if defaults:
            lines.append(f"Default args: {defaults}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        available = self.check_available()
        return (
            f"<VuraPlugin name={self.name!r} "
            f"category={self.category.value} "
            f"available={available}>"
        )


# ══════════════════════════════════════════════════════════════════════
# PLUGIN REGISTRY
# ══════════════════════════════════════════════════════════════════════

class PluginRegistry:
    """
    Registry for discovering and managing VURA plugins.

    Usage:
        registry = PluginRegistry()
        registry.discover()  # Auto-find plugins in app/plugins/

        # Run a plugin
        nmap = registry.get("nmap")
        if nmap and nmap.check_available():
            result = nmap.execute("example.com")
    """

    def __init__(self):
        self._plugins: dict[str, VuraPlugin] = {}

    def register(self, plugin: VuraPlugin) -> None:
        """Register a plugin instance."""
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> Optional[VuraPlugin]:
        """Get a plugin by name."""
        return self._plugins.get(name)

    def list_all(self) -> dict[str, VuraPlugin]:
        """Get all registered plugins."""
        return dict(self._plugins)

    def list_available(self) -> dict[str, VuraPlugin]:
        """Get plugins that are installed and usable."""
        return {
            name: plugin
            for name, plugin in self._plugins.items()
            if plugin.check_available()
        }

    def list_by_category(self, category: PluginCategory) -> list[VuraPlugin]:
        """Get plugins in a specific category."""
        return [
            plugin for plugin in self._plugins.values()
            if plugin.category == category
        ]

    def discover(self, plugin_dir: Optional[str] = None) -> int:
        """
        Auto-discover plugins in a directory.

        Scans the directory for Python files, imports them,
        and registers any VuraPlugin subclasses found.

        Returns:
            Number of plugins discovered.
        """
        import importlib
        import importlib.util
        from pathlib import Path

        if plugin_dir is None:
            plugin_dir = str(Path(__file__).parent)

        count = 0
        for path in Path(plugin_dir).glob("*.py"):
            if path.name.startswith("_") or path.name == "base.py":
                continue

            try:
                spec = importlib.util.spec_from_file_location(
                    f"vura_plugin_{path.stem}", str(path)
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)

                    # Find VuraPlugin subclasses
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (
                            isinstance(attr, type)
                            and issubclass(attr, VuraPlugin)
                            and attr is not VuraPlugin
                            and attr.name != "unnamed"
                        ):
                            self.register(attr())
                            count += 1

            except Exception:
                continue  # Skip plugins that fail to load

        return count

    def run_all(
        self,
        target: str,
        category: Optional[PluginCategory] = None,
        available_only: bool = True,
        **kwargs: Any,
    ) -> list[PluginResult]:
        """
        Run multiple plugins against a target.

        Parameters:
            target: Target to scan
            category: Only run plugins in this category (None = all)
            available_only: Skip plugins that aren't installed
            **kwargs: Passed to each plugin's execute method
        """
        results = []

        plugins = self._plugins.values()
        if category:
            plugins = [p for p in plugins if p.category == category]
        if available_only:
            plugins = [p for p in plugins if p.check_available()]

        for plugin in plugins:
            try:
                result = plugin.execute(target, **kwargs)
                results.append(result)
            except Exception as e:
                results.append(PluginResult(
                    plugin_name=plugin.name,
                    target=target,
                    success=False,
                    error=str(e),
                ))

        return results


# Global registry instance
registry = PluginRegistry()
