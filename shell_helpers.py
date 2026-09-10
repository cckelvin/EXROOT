"""EXROOT shell helpers: result display and CVE help listing."""

from __future__ import annotations

from typing import Any


def print_cve_help(engine) -> None:
    """List available CVE commands from the registry."""

    print()
    print("Available CVE commands:")
    print()

    commands = []

    if engine is not None:
        try:
            if not getattr(engine, "initialized", False):
                engine.initialize()
            commands = sorted(engine.registry.commands.keys())
        except Exception as error:
            print(f"[CVE] Unable to load command list: {error}")
            print()
            return

    if not commands:
        print("  (no commands registered)")
        print()
        return

    for name in commands:
        meta = engine.registry.get_command(name) or {}
        api = meta.get("api_function") or meta.get("api") or ""
        if api:
            print(f"  cve {name:<12} -> {api}")
        else:
            print(f"  cve {name}")

    print()
    print("Example: cve mkdir /tmp/demo")
    print()


def display_result(result: Any) -> None:
    """Display a result returned by the CVE engine."""

    if result is None:
        return

    if isinstance(result, dict):
        success = result.get("success")

        if success is False:
            error = result.get("error", "Command failed.")
            print(f"[CVE] Error: {error}")
            return

        payload = result
        for key in ("result", "output", "data"):
            if isinstance(payload, dict) and key in payload:
                payload = payload[key]

        if (
            isinstance(payload, dict)
            and "result" in payload
            and set(payload.keys()) <= {"success", "api", "result", "error"}
        ):
            payload = payload.get("result", payload)

        if isinstance(payload, dict) and "entries" in payload:
            path = payload.get("path", ".")
            print(f"{path}:")
            for entry in payload.get("entries") or []:
                if isinstance(entry, dict):
                    name = entry.get("name", entry)
                    kind = entry.get("type", "")
                    suffix = "/" if kind == "directory" else ""
                    print(f"  {name}{suffix}")
                else:
                    print(f"  {entry}")
            return

        if isinstance(payload, dict) and "path" in payload and len(payload) <= 5:
            path = payload.get("path")
            if payload.get("created") is True:
                print(f"Created: {path}")
            elif "size" in payload:
                print(f"Wrote: {path} ({payload.get('size')} bytes)")
            elif "content" in payload or "data" in payload:
                print(payload.get("content", payload.get("data", "")))
            else:
                print(path)
            return

        if isinstance(payload, dict) and (
            "content" in payload or "data" in payload or "body" in payload
        ):
            print(
                payload.get("content")
                or payload.get("data")
                or payload.get("body")
            )
            return

        if isinstance(payload, dict) and "stdout" in payload:
            if payload.get("stdout"):
                text = str(payload["stdout"])
                print(text, end="" if text.endswith("\n") else "\n")
            if payload.get("stderr"):
                text = str(payload["stderr"])
                print(text, end="" if text.endswith("\n") else "\n")
            return

        if isinstance(payload, (dict, list)):
            print(payload)
            return

        if payload is not None:
            print(str(payload))
            return

        if success is True:
            print("[CVE] Command completed successfully.")
            return

        print(result)
        return

    if isinstance(result, str):
        print(result)
        return

    print(result)
