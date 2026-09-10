"""
EXROOT Filesystem Runtime

Host filesystem operations used by the CVE engine.

This module performs actual filesystem operations.
It does not decide which CVE command is allowed to run.
That policy belongs to the Commands registry.
"""

from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path
from typing import Any


# ============================================================
# PATH HELPERS
# ============================================================

def _path(value: str | Path) -> Path:
    """Convert a value into a Path object."""

    if value is None:
        raise ValueError("A filesystem path is required.")

    value = str(value).strip()

    if not value:
        raise ValueError("Filesystem path cannot be empty.")

    return Path(value).expanduser()


# ============================================================
# DIRECTORY
# ============================================================

def mkdir(args: list[str], options: dict[str, Any] | None = None):
    """Create a directory."""

    if not args:
        raise ValueError("mkdir requires a path.")

    path = _path(args[0])

    parents = bool(
        (options or {}).get("parents", True)
    )

    path.mkdir(
        parents=parents,
        exist_ok=parents,
    )

    return {
        "success": True,
        "path": str(path.resolve()),
        "created": True,
    }


# ============================================================
# READ FILE
# ============================================================

def readFile(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Read a text file."""

    if not args:
        raise ValueError("readFile requires a path.")

    path = _path(args[0])

    if not path.is_file():
        raise FileNotFoundError(
            f"File not found: {path}"
        )

    encoding = (
        (options or {}).get(
            "encoding",
            "utf-8",
        )
    )

    data = path.read_text(
        encoding=encoding
    )

    return {
        "success": True,
        "path": str(path.resolve()),
        "data": data,
    }


# ============================================================
# WRITE FILE
# ============================================================

def writeFile(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Write text to a file."""

    if len(args) < 2:
        raise ValueError(
            "writeFile requires a path and data."
        )

    path = _path(args[0])
    data = args[1]

    encoding = (
        (options or {}).get(
            "encoding",
            "utf-8",
        )
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        str(data),
        encoding=encoding,
    )

    return {
        "success": True,
        "path": str(path.resolve()),
        "size": path.stat().st_size,
    }


# ============================================================
# DELETE
# ============================================================

def delete(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Delete a file or directory."""

    if not args:
        raise ValueError("delete requires a path.")

    path = _path(args[0])

    if not path.exists() and not path.is_symlink():
        raise FileNotFoundError(
            f"Path not found: {path}"
        )

    if path.is_dir() and not path.is_symlink():

        shutil.rmtree(path)

    else:

        path.unlink()

    return {
        "success": True,
        "path": str(path.resolve()),
        "deleted": True,
    }


# ============================================================
# COPY
# ============================================================

def copy(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Copy a file or directory."""

    if len(args) < 2:
        raise ValueError(
            "copy requires source and destination."
        )

    source = _path(args[0])
    destination = _path(args[1])

    if not source.exists():
        raise FileNotFoundError(
            f"Source not found: {source}"
        )

    if source.is_dir():

        shutil.copytree(
            source,
            destination,
            dirs_exist_ok=True,
        )

    else:

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        shutil.copy2(
            source,
            destination,
        )

    return {
        "success": True,
        "source": str(source.resolve()),
        "destination": str(
            destination.resolve()
        ),
    }


# ============================================================
# MOVE
# ============================================================

def move(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Move a file or directory."""

    if len(args) < 2:
        raise ValueError(
            "move requires source and destination."
        )

    source = _path(args[0])
    destination = _path(args[1])

    if not source.exists():
        raise FileNotFoundError(
            f"Source not found: {source}"
        )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    shutil.move(
        str(source),
        str(destination),
    )

    return {
        "success": True,
        "source": str(source),
        "destination": str(
            destination.resolve()
        ),
    }


# ============================================================
# STAT
# ============================================================

def stat(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Return information about a filesystem path."""

    if not args:
        raise ValueError("stat requires a path.")

    path = _path(args[0])

    if not path.exists():
        raise FileNotFoundError(
            f"Path not found: {path}"
        )

    info = path.stat()

    return {
        "success": True,
        "path": str(path.resolve()),
        "name": path.name,
        "type": (
            "directory"
            if path.is_dir()
            else "file"
        ),
        "size": info.st_size,
        "modified": info.st_mtime,
        "created": info.st_ctime,
    }


# ============================================================
# EXISTS
# ============================================================

def exists(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Check whether a path exists."""

    if not args:
        raise ValueError("exists requires a path.")

    path = _path(args[0])

    return {
        "success": True,
        "path": str(path),
        "exists": path.exists(),
    }


# ============================================================
# LIST
# ============================================================

def list(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """List directory contents."""

    path = (
        _path(args[0])
        if args
        else Path.cwd()
    )

    if not path.exists():
        raise FileNotFoundError(
            f"Path not found: {path}"
        )

    if not path.is_dir():
        raise NotADirectoryError(
            f"Not a directory: {path}"
        )

    entries = []

    for item in path.iterdir():

        entries.append(
            {
                "name": item.name,
                "path": str(item),
                "type": (
                    "directory"
                    if item.is_dir()
                    else "file"
                ),
            }
        )

    entries.sort(
        key=lambda item: (
            item["type"] != "directory",
            item["name"].lower(),
        )
    )

    return {
        "success": True,
        "path": str(path.resolve()),
        "entries": entries,
    }


# ============================================================
# CURRENT DIRECTORY
# ============================================================

def cwd(
    args: list[str] | None = None,
    options: dict[str, Any] | None = None,
):
    """Return the current working directory."""

    return {
        "success": True,
        "path": str(Path.cwd()),
    }


# ============================================================
# CHANGE DIRECTORY
# ============================================================

def chdir(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Change the current working directory."""

    if not args:
        raise ValueError("chdir requires a path.")

    path = _path(args[0])

    if not path.is_dir():
        raise NotADirectoryError(
            f"Not a directory: {path}"
        )

    os.chdir(path)

    return {
        "success": True,
        "path": str(Path.cwd()),
    }


# ============================================================
# HEAD
# ============================================================

def head(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Read the first lines of a file."""

    if not args:
        raise ValueError("head requires a file.")

    path = _path(args[0])

    lines = int(
        (options or {}).get(
            "lines",
            10,
        )
    )

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:

        data = "".join(
            file.readlines()[:lines]
        )

    return {
        "success": True,
        "path": str(path.resolve()),
        "data": data,
    }


# ============================================================
# TAIL
# ============================================================

def tail(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Read the last lines of a file."""

    if not args:
        raise ValueError("tail requires a file.")

    path = _path(args[0])

    lines = int(
        (options or {}).get(
            "lines",
            10,
        )
    )

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:

        data = "".join(
            file.readlines()[-lines:]
        )

    return {
        "success": True,
        "path": str(path.resolve()),
        "data": data,
    }


# ============================================================
# CHECKSUM
# ============================================================

def checksum(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Calculate a file checksum."""

    if not args:
        raise ValueError(
            "checksum requires a file."
        )

    path = _path(args[0])

    algorithm = (
        (options or {}).get(
            "algorithm",
            "sha256",
        )
        .lower()
    )

    try:
        digest = hashlib.new(
            algorithm
        )
    except ValueError:
        raise ValueError(
            f"Unsupported hash algorithm: {algorithm}"
        )

    with path.open("rb") as file:

        while True:

            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return {
        "success": True,
        "algorithm": algorithm,
        "checksum": digest.hexdigest(),
        "path": str(path.resolve()),
    }


# ============================================================
# WATCH
# ============================================================

def watch(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """
    Basic filesystem watch placeholder.

    A persistent watcher requires an event-loop/service
    architecture. This function reports the requested target
    without starting an unmanaged background process.
    """

    path = (
        _path(args[0])
        if args
        else Path.cwd()
    )

    if not path.exists():
        raise FileNotFoundError(
            f"Path not found: {path}"
        )

    return {
        "success": True,
        "watching": False,
        "path": str(path.resolve()),
        "message": (
            "Persistent filesystem watching "
            "will be provided by the EXROOT runtime service."
        ),
    }
