"""
EXROOT CVE Command Parser

Converts a user command such as:

    cve mkdir project

into structured data that the CVE engine can understand.
"""

from __future__ import annotations

import shlex
from typing import Any


# ============================================================
# PARSER ERRORS
# ============================================================

class CVEParserError(Exception):
    """Raised when a CVE command cannot be parsed."""


# ============================================================
# COMMAND PARSER
# ============================================================

def parse_command(command_line: str) -> dict[str, Any]:
    """
    Parse a CVE command.

    Example:

        cve mkdir project

    Returns:

        {
            "system": "cve",
            "command": "mkdir",
            "args": ["project"],
            "raw": "cve mkdir project"
        }
    """

    if not isinstance(command_line, str):
        raise CVEParserError("Command must be a string.")

    command_line = command_line.strip()

    if not command_line:
        raise CVEParserError("Command is empty.")

    # --------------------------------------------------------
    # Use shlex so quoted arguments work correctly.
    #
    # Example:
    #
    # cve mkdir "my project"
    #
    # becomes:
    #
    # ["cve", "mkdir", "my project"]
    # --------------------------------------------------------

    try:
        tokens = shlex.split(command_line)
    except ValueError as error:
        raise CVEParserError(
            f"Invalid command syntax: {error}"
        ) from error

    if not tokens:
        raise CVEParserError("Command is empty.")

    # --------------------------------------------------------
    # CVE system prefix
    # --------------------------------------------------------

    system = tokens[0].lower()

    if system != "cve":
        raise CVEParserError(
            "CVE commands must begin with 'cve'."
        )

    # --------------------------------------------------------
    # Command name
    # --------------------------------------------------------

    if len(tokens) < 2:
        raise CVEParserError(
            "No CVE command was specified."
        )

    command = tokens[1].lower()

    # --------------------------------------------------------
    # Arguments
    # --------------------------------------------------------

    args = tokens[2:]

    # --------------------------------------------------------
    # Return parsed command
    # --------------------------------------------------------

    return {
        "system": system,
        "command": command,
        "args": args,
        "raw": command_line,
    }


# ============================================================
# PARSE ARGUMENTS
# ============================================================

def parse_arguments(command_line: str) -> list[str]:
    """
    Return only the arguments from a CVE command.

    Example:

        cve mkdir project

    Returns:

        ["project"]
    """

    parsed = parse_command(command_line)

    return parsed["args"]


# ============================================================
# GET COMMAND NAME
# ============================================================

def get_command_name(command_line: str) -> str:
    """
    Return the command name.

    Example:

        cve mkdir project

    Returns:

        "mkdir"
    """

    parsed = parse_command(command_line)

    return parsed["command"]


# ============================================================
# VALIDATE CVE PREFIX
# ============================================================

def is_cve_command(command_line: str) -> bool:
    """
    Check whether a string is a CVE command.

    This does not verify whether the command actually exists.
    """

    if not isinstance(command_line, str):
        return False

    command_line = command_line.strip()

    if not command_line:
        return False

    try:
        tokens = shlex.split(command_line)
    except ValueError:
        return False

    if not tokens:
        return False

    return tokens[0].lower() == "cve"


# ============================================================
# NORMALIZE COMMAND
# ============================================================

def normalize_command(command_line: str) -> str:
    """
    Normalize a CVE command into a predictable format.

    Example:

        CVE MKDIR project

    becomes:

        cve mkdir project
    """

    parsed = parse_command(command_line)

    parts = [
        "cve",
        parsed["command"],
        *parsed["args"],
    ]

    return shlex.join(parts)


# ============================================================
# PARSE OPTION-STYLE ARGUMENTS
# ============================================================

def parse_options(args: list[str]) -> dict[str, Any]:
    """
    Separate simple command options from positional arguments.

    Example:

        [
            "project",
            "--parents",
            "--mode",
            "755"
        ]

    becomes approximately:

        {
            "args": ["project"],
            "options": {
                "parents": True,
                "mode": "755"
            }
        }

    This is intentionally generic.

    The command registry will eventually provide the actual
    argument schema for each command.
    """

    positional: list[str] = []
    options: dict[str, Any] = {}

    index = 0

    while index < len(args):

        value = args[index]

        # ----------------------------------------------------
        # --name=value
        # ----------------------------------------------------

        if value.startswith("--") and "=" in value:

            key, option_value = value[2:].split("=", 1)

            options[key] = option_value

            index += 1
            continue

        # ----------------------------------------------------
        # --flag
        # ----------------------------------------------------

        if value.startswith("--"):

            key = value[2:]

            # Check whether the next token is a value.
            if (
                index + 1 < len(args)
                and not args[index + 1].startswith("-")
            ):
                options[key] = args[index + 1]
                index += 2
                continue

            options[key] = True

            index += 1
            continue

        # ----------------------------------------------------
        # -x
        # ----------------------------------------------------

        if value.startswith("-") and value != "-":

            key = value[1:]

            # Check whether the next token is a value.
            if (
                index + 1 < len(args)
                and not args[index + 1].startswith("-")
            ):
                options[key] = args[index + 1]
                index += 2
                continue

            options[key] = True

            index += 1
            continue

        # ----------------------------------------------------
        # Positional argument
        # ----------------------------------------------------

        positional.append(value)

        index += 1

    return {
        "args": positional,
        "options": options,
    }


# ============================================================
# FULL PARSE
# ============================================================

def parse_full_command(command_line: str) -> dict[str, Any]:
    """
    Parse a CVE command and its generic options.

    Example:

        cve mkdir project --parents

    Returns structured information for the engine.
    """

    parsed = parse_command(command_line)

    argument_data = parse_options(parsed["args"])

    return {
        "system": parsed["system"],
        "command": parsed["command"],
        "args": argument_data["args"],
        "options": argument_data["options"],
        "raw": parsed["raw"],
    }


# ============================================================
# PARSER SELF-TEST
# ============================================================

def self_test() -> bool:
    """
    Run basic parser tests.

    Returns True when all tests pass.
    """

    # --------------------------------------------------------
    # Basic command
    # --------------------------------------------------------

    result = parse_command("cve mkdir project")

    assert result["system"] == "cve"
    assert result["command"] == "mkdir"
    assert result["args"] == ["project"]

    # --------------------------------------------------------
    # Multiple arguments
    # --------------------------------------------------------

    result = parse_command(
        "cve copy source.txt destination.txt"
    )

    assert result["command"] == "copy"
    assert result["args"] == [
        "source.txt",
        "destination.txt",
    ]

    # --------------------------------------------------------
    # Quoted argument
    # --------------------------------------------------------

    result = parse_command(
        'cve mkdir "my project"'
    )

    assert result["args"] == ["my project"]

    # --------------------------------------------------------
    # Options
    # --------------------------------------------------------

    result = parse_full_command(
        "cve mkdir project --parents"
    )

    assert result["command"] == "mkdir"
    assert result["args"] == ["project"]
    assert result["options"]["parents"] is True

    return True


# ============================================================
# MODULE TEST
# ============================================================

if __name__ == "__main__":

    print("EXROOT CVE Parser Test")
    print("----------------------")

    try:
        passed = self_test()

        if passed:
            print("Parser tests passed.")

    except AssertionError:
        print("Parser tests failed.")

    except Exception as error:
        print(f"Parser error: {error}")
