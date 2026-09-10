"""
EXROOT Process Runtime

Provides controlled process operations for CVE.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from typing import Any


# ============================================================
# COMMAND EXTRACTION
# ============================================================

def _command(
    args: list[str],
) -> list[str]:

    if not args:
        raise ValueError(
            "A process command is required."
        )

    return [str(value) for value in args]


# ============================================================
# SPAWN
# ============================================================

def spawn(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Start a process without waiting for completion."""

    command = _command(args)
    options = options or {}

    process = subprocess.Popen(
        command,
        cwd=options.get("cwd"),
        env=options.get("env"),
        stdin=subprocess.PIPE
        if options.get("stdin")
        else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    return {
        "success": True,
        "pid": process.pid,
        "command": command,
    }


# ============================================================
# EXEC
# ============================================================

def exec(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Execute a process and wait for completion."""

    command = _command(args)
    options = options or {}

    timeout = options.get(
        "timeout"
    )

    result = subprocess.run(
        command,
        cwd=options.get("cwd"),
        env=options.get("env"),
        capture_output=True,
        text=True,
        timeout=(
            float(timeout)
            if timeout is not None
            else None
        ),
    )

    return {
        "success": result.returncode == 0,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "command": command,
    }


# ============================================================
# KILL
# ============================================================

def kill(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Terminate a process by PID."""

    if not args:
        raise ValueError(
            "kill requires a process ID."
        )

    pid = int(args[0])

    if os.name == "nt":
        os.kill(
            pid,
            signal.SIGTERM,
        )
    else:
        os.kill(
            pid,
            signal.SIGTERM,
        )

    return {
        "success": True,
        "pid": pid,
        "terminated": True,
    }


# ============================================================
# PROCESS LIST
# ============================================================

def list(
    args: list[str] | None = None,
    options: dict[str, Any] | None = None,
):
    """
    List processes.

    Uses platform-native commands rather than assuming
    Linux utilities exist.
    """

    if sys.platform.startswith("win"):

        result = subprocess.run(
            [
                "tasklist",
                "/FO",
                "CSV",
                "/NH",
            ],
            capture_output=True,
            text=True,
        )

        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    result = subprocess.run(
        [
            "ps",
            "-eo",
            "pid,ppid,user,%cpu,%mem,command",
        ],
        capture_output=True,
        text=True,
    )

    return {
        "success": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


# ============================================================
# PROCESS INFO
# ============================================================

def info(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Return basic information about a process."""

    if not args:
        raise ValueError(
            "info requires a process ID."
        )

    pid = int(args[0])

    if sys.platform.startswith("win"):

        result = subprocess.run(
            [
                "tasklist",
                "/FI",
                f"PID eq {pid}",
            ],
            capture_output=True,
            text=True,
        )

    else:

        result = subprocess.run(
            [
                "ps",
                "-p",
                str(pid),
                "-f",
            ],
            capture_output=True,
            text=True,
        )

    return {
        "success": result.returncode == 0,
        "pid": pid,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


# ============================================================
# STDIN
# ============================================================

def stdin(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """
    Send stdin to an existing process.

    The first argument is the PID.

    Persistent process handles will be added to the EXROOT
    process manager later.
    """

    if len(args) < 2:
        raise ValueError(
            "stdin requires PID and data."
        )

    pid = int(args[0])
    data = " ".join(args[1:])

    return {
        "success": False,
        "pid": pid,
        "message": (
            "Persistent process handles are not "
            "implemented in this runtime version."
        ),
        "data": data,
    }


# ============================================================
# STDOUT
# ============================================================

def stdout(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Return process output information."""

    return {
        "success": False,
        "message": (
            "Persistent process handles are not "
            "implemented in this runtime version."
        ),
    }


# ============================================================
# STDERR
# ============================================================

def stderr(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Return process error output information."""

    return {
        "success": False,
        "message": (
            "Persistent process handles are not "
            "implemented in this runtime version."
        ),
    }
