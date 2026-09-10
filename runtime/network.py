"""
EXROOT Network Runtime

Host networking primitives used by CVE.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import urllib.request
from typing import Any


# ============================================================
# HTTP REQUEST
# ============================================================

def httpRequest(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Perform an HTTP request."""

    if not args:
        raise ValueError(
            "httpRequest requires a URL."
        )

    url = args[0]
    options = options or {}

    method = options.get(
        "method",
        "GET",
    ).upper()

    headers = options.get(
        "headers",
        {},
    )

    body = options.get(
        "body"
    )

    timeout = float(
        options.get(
            "timeout",
            30,
        )
    )

    if body is not None:

        if isinstance(
            body,
            (dict, list),
        ):

            body = json.dumps(
                body
            )

        body = str(body).encode(
            "utf-8"
        )

    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method=method,
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:

            data = response.read()

            try:
                body_text = data.decode(
                    "utf-8"
                )
            except UnicodeDecodeError:
                body_text = data.decode(
                    "utf-8",
                    errors="replace",
                )

            return {
                "success": True,
                "status": response.status,
                "headers": dict(
                    response.headers
                ),
                "body": body_text,
            }

    except Exception as error:

        return {
            "success": False,
            "error": str(error),
        }


# ============================================================
# TCP CONNECT
# ============================================================

def tcpConnect(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Test a TCP connection."""

    if len(args) < 2:
        raise ValueError(
            "tcpConnect requires host and port."
        )

    host = args[0]
    port = int(args[1])

    options = options or {}

    timeout = float(
        options.get(
            "timeout",
            5,
        )
    )

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    sock.settimeout(timeout)

    try:

        result = sock.connect_ex(
            (host, port)
        )

        return {
            "success": result == 0,
            "host": host,
            "port": port,
            "open": result == 0,
            "code": result,
        }

    finally:

        sock.close()


# ============================================================
# TCP LISTEN
# ============================================================

def tcpListen(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """
    Create a listening socket.

    This returns information about the socket rather than
    creating an unmanaged long-running network service.
    """

    if not args:
        raise ValueError(
            "tcpListen requires a port."
        )

    port = int(args[0])

    host = "0.0.0.0"

    if len(args) > 1:
        host = args[1]

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    sock.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1,
    )

    sock.bind(
        (host, port)
    )

    sock.listen(1)

    actual_host, actual_port = (
        sock.getsockname()
    )

    # Close immediately. Persistent listeners belong
    # in the EXROOT service/process manager.
    sock.close()

    return {
        "success": True,
        "host": actual_host,
        "port": actual_port,
        "listening": False,
        "message": (
            "Persistent network listeners are "
            "managed by the EXROOT runtime service."
        ),
    }


# ============================================================
# DNS LOOKUP
# ============================================================

def dnsLookup(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Resolve a hostname."""

    if not args:
        raise ValueError(
            "dnsLookup requires a hostname."
        )

    hostname = args[0]

    results = socket.getaddrinfo(
        hostname,
        None,
    )

    addresses = sorted(
        {
            item[4][0]
            for item in results
        }
    )

    return {
        "success": True,
        "hostname": hostname,
        "addresses": addresses,
    }


# ============================================================
# ROUTE
# ============================================================

def route(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Inspect the host routing table."""

    if sys.platform.startswith("win"):

        command = [
            "route",
            "print",
        ]

    else:

        command = [
            "ip",
            "route",
        ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    return {
        "success": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


# ============================================================
# PORT INSPECTION
# ============================================================

def portInspect(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Inspect network ports using host tools."""

    if sys.platform.startswith("win"):

        command = [
            "netstat",
            "-ano",
        ]

    else:

        command = [
            "ss",
            "-tulnp",
        ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    return {
        "success": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


# ============================================================
# PORT CLOSE
# ============================================================

def portClose(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """
    Close a port.

    A port normally belongs to a process, so safely closing
    it requires identifying and terminating/blocking the
    owning service. This runtime version only reports the
    port rather than killing an unknown process.
    """

    if not args:
        raise ValueError(
            "portClose requires a port."
        )

    port = int(args[0])

    return {
        "success": False,
        "port": port,
        "message": (
            "Port ownership must be resolved by the "
            "EXROOT network manager before a port is closed."
        ),
    }"""
EXROOT Network Runtime

Host networking primitives used by CVE.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import urllib.request
from typing import Any


# ============================================================
# HTTP REQUEST
# ============================================================

def httpRequest(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Perform an HTTP request."""

    if not args:
        raise ValueError(
            "httpRequest requires a URL."
        )

    url = args[0]
    options = options or {}

    method = options.get(
        "method",
        "GET",
    ).upper()

    headers = options.get(
        "headers",
        {},
    )

    body = options.get(
        "body"
    )

    timeout = float(
        options.get(
            "timeout",
            30,
        )
    )

    if body is not None:

        if isinstance(
            body,
            (dict, list),
        ):

            body = json.dumps(
                body
            )

        body = str(body).encode(
            "utf-8"
        )

    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method=method,
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:

            data = response.read()

            try:
                body_text = data.decode(
                    "utf-8"
                )
            except UnicodeDecodeError:
                body_text = data.decode(
                    "utf-8",
                    errors="replace",
                )

            return {
                "success": True,
                "status": response.status,
                "headers": dict(
                    response.headers
                ),
                "body": body_text,
            }

    except Exception as error:

        return {
            "success": False,
            "error": str(error),
        }


# ============================================================
# TCP CONNECT
# ============================================================

def tcpConnect(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Test a TCP connection."""

    if len(args) < 2:
        raise ValueError(
            "tcpConnect requires host and port."
        )

    host = args[0]
    port = int(args[1])

    options = options or {}

    timeout = float(
        options.get(
            "timeout",
            5,
        )
    )

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    sock.settimeout(timeout)

    try:

        result = sock.connect_ex(
            (host, port)
        )

        return {
            "success": result == 0,
            "host": host,
            "port": port,
            "open": result == 0,
            "code": result,
        }

    finally:

        sock.close()


# ============================================================
# TCP LISTEN
# ============================================================

def tcpListen(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """
    Create a listening socket.

    This returns information about the socket rather than
    creating an unmanaged long-running network service.
    """

    if not args:
        raise ValueError(
            "tcpListen requires a port."
        )

    port = int(args[0])

    host = "0.0.0.0"

    if len(args) > 1:
        host = args[1]

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    sock.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1,
    )

    sock.bind(
        (host, port)
    )

    sock.listen(1)

    actual_host, actual_port = (
        sock.getsockname()
    )

    # Close immediately. Persistent listeners belong
    # in the EXROOT service/process manager.
    sock.close()

    return {
        "success": True,
        "host": actual_host,
        "port": actual_port,
        "listening": False,
        "message": (
            "Persistent network listeners are "
            "managed by the EXROOT runtime service."
        ),
    }


# ============================================================
# DNS LOOKUP
# ============================================================

def dnsLookup(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Resolve a hostname."""

    if not args:
        raise ValueError(
            "dnsLookup requires a hostname."
        )

    hostname = args[0]

    results = socket.getaddrinfo(
        hostname,
        None,
    )

    addresses = sorted(
        {
            item[4][0]
            for item in results
        }
    )

    return {
        "success": True,
        "hostname": hostname,
        "addresses": addresses,
    }


# ============================================================
# ROUTE
# ============================================================

def route(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Inspect the host routing table."""

    if sys.platform.startswith("win"):

        command = [
            "route",
            "print",
        ]

    else:

        command = [
            "ip",
            "route",
        ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    return {
        "success": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


# ============================================================
# PORT INSPECTION
# ============================================================

def portInspect(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """Inspect network ports using host tools."""

    if sys.platform.startswith("win"):

        command = [
            "netstat",
            "-ano",
        ]

    else:

        command = [
            "ss",
            "-tulnp",
        ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    return {
        "success": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


# ============================================================
# PORT CLOSE
# ============================================================

def portClose(
    args: list[str],
    options: dict[str, Any] | None = None,
):
    """
    Close a port.

    A port normally belongs to a process, so safely closing
    it requires identifying and terminating/blocking the
    owning service. This runtime version only reports the
    port rather than killing an unknown process.
    """

    if not args:
        raise ValueError(
            "portClose requires a port."
        )

    port = int(args[0])

    return {
        "success": False,
        "port": port,
        "message": (
            "Port ownership must be resolved by the "
            "EXROOT network manager before a port is closed."
        ),
    }
