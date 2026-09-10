"""
EXROOT Package Runtime

Provides package-manager operations.

The runtime detects the host package manager rather than
assuming that the host is Linux.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from typing import Any


# ============================================================
# PACKAGE MANAGER DETECTION
# ============================================================

def detect_manager() -> str | None:

    managers = []

    if sys.platform.startswith("win"):

        managers = [
            "winget",
            "choco",
            "scoop",
        ]

    elif sys.platform.startswith("darwin"):

        managers = [
            "brew",
        ]

    else:

        managers = [
            "apt",
            "dnf",
            "yum",
            "pacman",
            "apk",
        ]

    for manager in managers:

        if shutil.which(manager):
            return manager

    return None


# ============================================================
# RUN PACKAGE MANAGER
# ============================================================

def _run(
    command: list[str],
):

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    return {
        "success": result.returncode == 0,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "command": command,
    }


# ============================================================
# INSTALL
# ============================================================

def install(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Install a package."""

    if not args:
        raise ValueError(
            "install requires a package."
        )

    manager = detect_manager()

    if not manager:
        raise RuntimeError(
            "No supported package manager was found."
        )

    package = args[0]

    if manager == "winget":

        command = [
            "winget",
            "install",
            package,
        ]

    elif manager == "choco":

        command = [
            "choco",
            "install",
            package,
            "-y",
        ]

    elif manager == "scoop":

        command = [
            "scoop",
            "install",
            package,
        ]

    elif manager == "brew":

        command = [
            "brew",
            "install",
            package,
        ]

    elif manager in {
        "apt",
        "dnf",
        "yum",
        "pacman",
        "apk",
    }:

        command = [
            manager,
            "install",
            package,
        ]

        if manager == "apt":
            command.insert(1, "-y")

        elif manager in {
            "dnf",
            "yum",
        }:
            command.insert(1, "-y")

        elif manager == "apk":
            command.insert(1, "add")

    else:

        raise RuntimeError(
            f"Unsupported package manager: {manager}"
        )

    return _run(command)


# ============================================================
# REMOVE
# ============================================================

def remove(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Remove a package."""

    if not args:
        raise ValueError(
            "remove requires a package."
        )

    manager = detect_manager()

    if not manager:
        raise RuntimeError(
            "No supported package manager was found."
        )

    package = args[0]

    if manager == "winget":

        command = [
            "winget",
            "uninstall",
            package,
        ]

    elif manager in {
        "choco",
        "scoop",
        "brew",
        "apt",
        "dnf",
        "yum",
        "pacman",
    }:

        command = [
            manager,
            "remove",
            package,
        ]

        if manager == "apt":
            command.insert(1, "-y")

        elif manager in {
            "dnf",
            "yum",
        }:
            command.insert(1, "-y")

    elif manager == "apk":

        command = [
            "apk",
            "del",
            package,
        ]

    else:

        raise RuntimeError(
            f"Unsupported package manager: {manager}"
        )

    return _run(command)


# ============================================================
# UPDATE
# ============================================================

def update(
    args: list[str] | None = None,
    options: dict[str, Any] | None = None,
):
    """Update package information/packages."""

    manager = detect_manager()

    if not manager:
        raise RuntimeError(
            "No supported package manager was found."
        )

    if manager == "winget":

        command = [
            "winget",
            "upgrade",
            "--all",
        ]

    elif manager == "choco":

        command = [
            "choco",
            "upgrade",
            "all",
            "-y",
        ]

    elif manager == "scoop":

        command = [
            "scoop",
            "update",
            "*",
        ]

    elif manager == "brew":

        command = [
            "brew",
            "update",
        ]

    elif manager == "apt":

        command = [
            "apt",
            "update",
        ]

    elif manager in {
        "dnf",
        "yum",
    }:

        command = [
            manager,
            "update",
            "-y",
        ]

    elif manager == "pacman":

        command = [
            "pacman",
            "-Syu",
        ]

    elif manager == "apk":

        command = [
            "apk",
            "update",
        ]

    else:

        raise RuntimeError(
            f"Unsupported package manager: {manager}"
        )

    return _run(command)


# ============================================================
# SEARCH
# ============================================================

def search(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Search for a package."""

    if not args:
        raise ValueError(
            "search requires a query."
        )

    manager = detect_manager()

    if not manager:
        raise RuntimeError(
            "No supported package manager was found."
        )

    query = args[0]

    if manager == "winget":

        command = [
            "winget",
            "search",
            query,
        ]

    elif manager == "choco":

        command = [
            "choco",
            "search",
            query,
        ]

    elif manager == "scoop":

        command = [
            "scoop",
            "search",
            query,
        ]

    elif manager == "brew":

        command = [
            "brew",
            "search",
            query,
        ]

    elif manager == "apt":

        command = [
            "apt-cache",
            "search",
            query,
        ]

    elif manager in {
        "dnf",
        "yum",
    }:

        command = [
            manager,
            "search",
            query,
        ]

    elif manager == "pacman":

        command = [
            "pacman",
            "-Ss",
            query,
        ]

    elif manager == "apk":

        command = [
            "apk",
            "search",
            query,
        ]

    else:

        raise RuntimeError(
            f"Unsupported package manager: {manager}"
        )

    return _run(command)


# ============================================================
# LIST
# ============================================================

def list(
    args: list[str] | None = None,
    options: dict[str, Any] | None = None,
):
    """List installed packages."""

    manager = detect_manager()

    if not manager:
        raise RuntimeError(
            "No supported package manager was found."
        )

    if manager == "winget":

        command = [
            "winget",
            "list",
        ]

    elif manager == "choco":

        command = [
            "choco",
            "list",
            "--local-only",
        ]

    elif manager == "scoop":

        command = [
            "scoop",
            "list",
        ]

    elif manager == "brew":

        command = [
            "brew",
            "list",
        ]

    elif manager == "apt":

        command = [
            "dpkg-query",
            "-W",
        ]

    elif manager in {
        "dnf",
        "yum",
    }:

        command = [
            manager,
            "list",
            "installed",
        ]

    elif manager == "pacman":

        command = [
            "pacman",
            "-Q",
        ]

    elif manager == "apk":

        command = [
            "apk",
            "info",
        ]

    else:

        raise RuntimeError(
            f"Unsupported package manager: {manager}"
        )

    return _run(command)
