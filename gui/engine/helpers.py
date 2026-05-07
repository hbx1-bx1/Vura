"""
VURA GUI — Engine Helpers
═══════════════════════════════════
Terminal detection, launching, and ANSI cleaning utilities.
Used by the hybrid GhostEngine wrapper.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import platform
from pathlib import Path
from typing import Optional, Tuple, Any


IS_WIN = os.name == "nt"


def clean_ansi(text: str) -> str:
    """Remove ANSI escape codes and control characters."""
    text = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)


def find_terminal() -> Optional[str]:
    """
    Detect the best available terminal emulator.

    Returns:
        Terminal executable name or None
    """
    if IS_WIN:
        if shutil.which("wt"):
            return "wt"
        if shutil.which("pwsh"):
            return "pwsh"
        if shutil.which("powershell"):
            return "powershell"
        return "cmd"

    if platform.system() == "Darwin":
        if shutil.which("iTerm2") or Path("/Applications/iTerm.app").exists():
            return "iterm2"
        return "terminal.app"

    # Linux
    for term in [
        "qterminal", "x-terminal-emulator", "xfce4-terminal",
        "gnome-terminal", "konsole", "mate-terminal",
        "lxterminal", "xterm", "terminator", "alacritty", "kitty",
    ]:
        if shutil.which(term):
            return term
    return None


def launch_terminal(cmd: str, terminal: str) -> Tuple[Any, str]:
    """
    Launch a terminal with the given command.

    Parameters:
        cmd: Shell command to execute
        terminal: Terminal emulator name

    Returns:
        (subprocess.Popen, terminal_name)
    """
    if IS_WIN:
        if terminal == "wt":
            p = subprocess.Popen(
                ["wt", "powershell", "-NoExit", "-Command", cmd],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
        elif terminal in ("pwsh", "powershell"):
            p = subprocess.Popen(
                [terminal, "-NoExit", "-Command", cmd],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
        else:
            p = subprocess.Popen(
                ["cmd", "/k", cmd],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
        return p, terminal

    if platform.system() == "Darwin":
        osa_cmd = cmd.replace('\\', '\\\\').replace('"', '\\"')
        if terminal == "iterm2":
            ascript = (
                'tell application "iTerm"\n'
                '  activate\n'
                '  set newWindow to (create window with default profile)\n'
                '  tell current session of newWindow\n'
                f'    write text "{osa_cmd}"\n'
                '  end tell\n'
                'end tell'
            )
        else:
            ascript = (
                'tell application "Terminal"\n'
                '  activate\n'
                f'  do script "{osa_cmd}"\n'
                'end tell'
            )
        p = subprocess.Popen(["osascript", "-e", ascript])
        return p, terminal

    # Linux
    if "gnome-terminal" in terminal:
        p = subprocess.Popen([terminal, "--title=VURA Ghost", "--", "bash", "-c", cmd])
    elif "konsole" in terminal:
        p = subprocess.Popen([terminal, "-e", "bash", "-c", cmd])
    elif "xterm" in terminal:
        p = subprocess.Popen([terminal, "-T", "VURA Ghost", "-e", "bash", "-c", cmd])
    else:
        p = subprocess.Popen([terminal, "-e", "bash", "-c", cmd])
    return p, terminal
