"""
EXROOT - Main Application Entry Point

EXROOT architecture:

    User
      ↓
    CVE Shell
      ↓
    CVE Parser
      ↓
    CVE Engine
      ↓
    CVE API
      ↓
    Runtime
      ↓
    Host Operating System

Maple will later sit above CVE and generate CVE commands
after analyzing terminal output.
"""

from __future__ import annotations

import sys
import os
import platform
from pathlib import Path


# ============================================================
# EXROOT INFORMATION
# ============================================================

EXROOT_NAME = "EXROOT"
EXROOT_VERSION = "0.1.0"


# ============================================================
# PROJECT PATHS
# ============================================================

ROOT_DIR = Path(__file__).resolve().parent

CVE_DIR = ROOT_DIR / "cve"
MAPLE_DIR = ROOT_DIR / "maple"
RUNTIME_DIR = ROOT_DIR / "runtime"
UI_DIR = ROOT_DIR / "ui"


# ============================================================
# IMPORT CVE COMPONENTS
# ============================================================

try:
    from cve.parser import parse_command
except ImportError:
    parse_command = None

try:
    from cve.engine import CVEEngine
except ImportError:
    CVEEngine = None


# ============================================================
# TERMINAL DISPLAY
# ============================================================

def print_banner() -> None:
    """Display the EXROOT startup banner."""

    print()
    print("=" * 60)
    print("                         EXROOT")
    print("=" * 60)
    print(f"Version : {EXROOT_VERSION}")
    print(f"System  : {platform.system()}")
    print(f"Machine : {platform.machine()}")
    print(f"Python  : {platform.python_version()}")
    print("=" * 60)
    print()
    print("CVE environment starting...")
    print()


def print_help() -> None:
    """Display basic EXROOT shell help."""

    print()
    print("EXROOT commands:")
    print()
    print("  cve <command> [arguments]")
    print("      Execute a CVE command.")
    print()
    print("  help")
    print("      Show this help message.")
    print()
    print("  version")
    print("      Show EXROOT version.")
    print()
    print("  system")
    print("      Show host system information.")
    print()
    print("  clear")
    print("      Clear the terminal.")
    print()
    print("  exit")
    print("      Exit EXROOT.")
    print()


def print_version() -> None:
    """Display EXROOT version."""

    print(f"{EXROOT_NAME} {EXROOT_VERSION}")


def print_system_info() -> None:
    """Display host system information."""

    print()
    print("System Information")
    print("------------------")
    print(f"Operating System : {platform.system()}")
    print(f"OS Release      : {platform.release()}")
    print(f"OS Version      : {platform.version()}")
    print(f"Architecture    : {platform.machine()}")
    print(f"Processor       : {platform.processor()}")
    print(f"Python          : {platform.python_version()}")
    print(f"EXROOT Root     : {ROOT_DIR}")
    print()


def clear_terminal() -> None:
    """Clear the terminal screen."""

    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


# ============================================================
# ENGINE INITIALIZATION
# ============================================================

def create_engine():
    """
    Create the CVE engine.

    The engine is responsible for:

        command
           ↓
        registry
           ↓
        API
           ↓
        runtime
           ↓
        host OS

    main.py does not implement individual commands.
    """

    if CVEEngine is None:
        return None

    try:
        return CVEEngine()
    except TypeError:
        # Allows the engine to be implemented incrementally.
        try:
            return CVEEngine(ROOT_DIR)
        except Exception:
            return None
    except Exception as error:
        print(f"[EXROOT] Engine initialization error: {error}")
        return None


# ============================================================
# COMMAND EXECUTION
# ============================================================

def execute_cve_command(command_line: str, engine) -> None:
    """
    Execute a CVE command.

    Example:

        cve mkdir project

    The actual command resolution belongs to the CVE engine.
    """

    if not command_line.strip():
        return

    if not command_line.strip().startswith("cve "):
        print("[CVE] Commands must begin with 'cve'.")
        print("Example: cve mkdir project")
        return

    # --------------------------------------------------------
    # Parse command
    # --------------------------------------------------------

    if parse_command is None:
        print("[CVE] Parser is not available.")
        return

    try:
        parsed = parse_command(command_line)
    except Exception as error:
        print(f"[CVE] Parser error: {error}")
        return

    # --------------------------------------------------------
    # Display parser errors
    # --------------------------------------------------------

    if parsed is None:
        print("[CVE] Unable to parse command.")
        return

    # --------------------------------------------------------
    # Execute through engine
    # --------------------------------------------------------

    if engine is None:
        print("[CVE] Engine is not available.")
        print("[CVE] The command was parsed but cannot be executed yet.")
        return

    try:

        # Preferred engine interface.
        if hasattr(engine, "execute"):
            result = engine.execute(parsed)

        # Alternative interface for incremental development.
        elif hasattr(engine, "run"):
            result = engine.run(parsed)

        else:
            print("[CVE] Engine has no execute/run method.")
            return

        display_result(result)

    except Exception as error:
        print(f"[CVE] Execution error: {error}")


# ============================================================
# RESULT DISPLAY
# ============================================================

def display_result(result) -> None:
    """Display a result returned by the CVE engine."""

    if result is None:
        return

    # Dictionary result
    if isinstance(result, dict):

        success = result.get("success")

        if success is False:
            error = result.get("error", "Command failed.")
            print(f"[CVE] Error: {error}")
            return

        # Normal result output
        output = result.get("output")

        if output is not None:
            if isinstance(output, (dict, list)):
                print(output)
            else:
                print(str(output))

        # Some APIs return data instead of output.
        elif "data" in result:
            data = result["data"]

            if isinstance(data, (dict, list)):
                print(data)
            else:
                print(str(data))

        # Generic result
        elif success is True:
            print("[CVE] Command completed successfully.")

        else:
            print(result)

        return

    # String result
    if isinstance(result, str):
        print(result)
        return

    # Other result types
    print(result)


# ============================================================
# EXROOT SHELL
# ============================================================

def run_shell() -> None:
    """
    Start the EXROOT interactive shell.

    The shell itself does not implement CVE commands.

    It only:

        1. receives user input
        2. identifies EXROOT shell commands
        3. sends CVE commands to the parser/engine
    """

    engine = create_engine()

    while True:

        try:
            command_line = input("exroot> ")

        except KeyboardInterrupt:
            print()
            print("Use 'exit' to close EXROOT.")
            continue

        except EOFError:
            print()
            break

        command_line = command_line.strip()

        if not command_line:
            continue

        # ----------------------------------------------------
        # Built-in EXROOT commands
        # ----------------------------------------------------

        lower_command = command_line.lower()

        if lower_command in ("exit", "quit"):
            print("EXROOT shutting down.")
            break

        if lower_command == "help":
            print_help()
            continue

        if lower_command == "version":
            print_version()
            continue

        if lower_command == "system":
            print_system_info()
            continue

        if lower_command == "clear":
            clear_terminal()
            continue

        # ----------------------------------------------------
        # CVE command
        # ----------------------------------------------------

        if lower_command.startswith("cve "):
            execute_cve_command(command_line, engine)
            continue

        # ----------------------------------------------------
        # Invalid shell input
        # ----------------------------------------------------

        print(
            "[EXROOT] Unknown input. "
            "Use 'help' or enter a command beginning with 'cve'."
        )


# ============================================================
# SINGLE COMMAND MODE
# ============================================================

def run_single_command(command_line: str) -> None:
    """
    Execute one CVE command and then exit.

    This allows:

        python main.py "cve mkdir project"

    """

    engine = create_engine()
    execute_cve_command(command_line, engine)


# ============================================================
# STARTUP CHECKS
# ============================================================

def startup_checks() -> bool:
    """
    Verify that the basic EXROOT structure exists.

    These checks do not create or modify anything.
    """

    required_paths = [
        CVE_DIR,
        RUNTIME_DIR,
        MAPLE_DIR,
        UI_DIR,
    ]

    missing = []

    for path in required_paths:
        if not path.exists():
            missing.append(path)

    if missing:

        print("[EXROOT] Warning: missing directories:")

        for path in missing:
            print(f"  - {path}")

        print()

        # Do not stop startup.
        # Some components may be added later.

    return True


# ============================================================
# APPLICATION START
# ============================================================

def main() -> None:
    """
    Main EXROOT application entry point.
    """

    startup_checks()

    # --------------------------------------------------------
    # Single-command mode
    # --------------------------------------------------------

    if len(sys.argv) > 1:

        command_line = " ".join(sys.argv[1:])

        if command_line.lower() in ("--version", "-v"):
            print_version()
            return

        if command_line.lower() in ("--help", "-h"):
            print_help()
            return

        run_single_command(command_line)
        return

    # --------------------------------------------------------
    # Interactive mode
    # --------------------------------------------------------

    print_banner()
    run_shell()


# ============================================================
# PYTHON ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
