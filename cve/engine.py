"""
EXROOT CVE Engine

Execution flow:

CVE command
    ↓
Registry
    ↓
API Function
    ↓
CVE API
    ↓
Runtime Function
    ↓
Host OS
"""

from typing import Any, Dict, Optional

from cve.registry import CVERegistry
from cve.api import CVEAPI, CVEAPIError


class CVEEngineError(Exception):
    """Raised when CVE command execution fails."""


class CVEEngine:
    """Main execution engine for CVE commands."""

    def __init__(
        self,
        registry: Optional[CVERegistry] = None,
        api: Optional[CVEAPI] = None,
    ):
        self.registry = registry or CVERegistry()
        self.api = api or CVEAPI()

        self.initialized = False

    def initialize(self) -> Dict[str, Any]:
        """Initialize the CVE registry."""

        result = self.registry.load()

        self.initialized = True

        return {
            "success": True,
            "registry": result,
            "api": self.api.status(),
        }

    def execute(self, parsed_command: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a parsed CVE command.

        Expected input:

        {
            "system": "cve",
            "command": "mkdir",
            "args": ["project"],
            "raw": "cve mkdir project"
        }
        """

        if not self.initialized:
            self.initialize()

        command_name = parsed_command.get("command")
        args = parsed_command.get("args", [])
        raw = parsed_command.get("raw", "")

        if not command_name:
            return self._error(
                "No CVE command was provided."
            )

        command = self.registry.get_command(command_name)

        if not command:
            return self._error(
                f"Unknown CVE command: {command_name}"
            )

        status = str(command.get("status", "active")).lower()

        if status in {
            "disabled",
            "inactive",
            "deprecated",
            "blocked",
        }:
            return self._error(
                f"CVE command '{command_name}' is not available.",
                command=command_name,
                status=status,
            )

        confirmation_required = self._to_bool(
            command.get("confirmation_required")
        )

        if confirmation_required:
            confirmation_type = command.get(
                "confirmation_type",
                "standard",
            )

            confirmation_prompt = command.get(
                "confirmation_prompt"
            )

            return {
                "success": False,
                "status": "confirmation_required",
                "command": command_name,
                "confirmation_type": confirmation_type,
                "prompt": confirmation_prompt
                or f"Confirm execution of: {raw}",
            }

        resolved = self.registry.resolve_api_for_command(
            command
        )

        if not resolved:
            resolved = command.get("api_function") or command.get("api")

        if not resolved:
            return self._error(
                f"No API function is mapped to CVE command "
                f"'{command_name}'.",
                command=command_name,
            )

        if isinstance(resolved, dict):
            api_function = resolved
            api_name = (
                resolved.get("function")
                or resolved.get("name")
                or resolved.get("api")
            )
        else:
            api_name = str(resolved)
            api_function = self.registry.get_api_function(api_name)

        if not api_name:
            return self._error(
                f"Unable to determine API function name for "
                f"CVE command '{command_name}'.",
                command=command_name,
            )

        if api_function is None:
            api_function = self.registry.get_api_function(api_name)

        if not self.api.exists(api_name):
            return self._error(
                f"API function '{api_name}' has no operational "
                f"implementation in the CVE API.",
                command=command_name,
                api=api_name,
            )

        runtime_name = None
        if api_function:
            runtime_meta = self.registry.resolve_runtime_for_api(
                api_function
            )
            if isinstance(runtime_meta, dict):
                runtime_name = (
                    runtime_meta.get("runtime_function")
                    or runtime_meta.get("function")
                    or runtime_meta.get("name")
                )
            elif runtime_meta is not None:
                runtime_name = str(runtime_meta)

        if runtime_name is None:
            runtime_name = api_name

        api_args = list(args)

        try:
            result = self.api.call(
                api_name,
                api_args,
                {},
            )

        except CVEAPIError as exc:
            return self._error(
                str(exc),
                command=command_name,
                api=api_name,
                runtime=runtime_name,
            )

        except Exception as exc:
            return self._error(
                f"Execution failed: {exc}",
                command=command_name,
                api=api_name,
                runtime=runtime_name,
            )

        return {
            "success": True,
            "status": "executed",
            "command": command_name,
            "args": api_args,
            "api": api_name,
            "runtime": runtime_name,
            "result": result,
        }

    def command_info(
        self,
        command_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Return registry information for a CVE command."""

        command = self.registry.get_command(command_name)

        if not command:
            return None

        resolved = self.registry.resolve_api_for_command(
            command
        )

        api_function = None
        api_name = None

        if isinstance(resolved, dict):
            api_function = resolved
            api_name = (
                resolved.get("function")
                or resolved.get("name")
                or resolved.get("api")
            )
        elif resolved is not None:
            api_name = str(resolved)
            api_function = self.registry.get_api_function(api_name)

        if api_function is None and api_name:
            api_function = self.registry.get_api_function(api_name)

        if api_name is None and isinstance(api_function, dict):
            api_name = (
                api_function.get("function")
                or api_function.get("name")
            )

        runtime_meta = None
        runtime_name = None

        if api_function:
            runtime_meta = self.registry.resolve_runtime_for_api(
                api_function
            )
            if isinstance(runtime_meta, dict):
                runtime_name = (
                    runtime_meta.get("runtime_function")
                    or runtime_meta.get("function")
                    or runtime_meta.get("name")
                )
            elif runtime_meta is not None:
                runtime_name = str(runtime_meta)

        return {
            "command": command,
            "api": api_function,
            "api_name": api_name,
            "runtime": runtime_meta,
            "runtime_name": runtime_name,
            "operational_api": (
                self.api.exists(api_name)
                if api_name
                else False
            ),
        }

    def status(self) -> Dict[str, Any]:
        """Return engine status."""

        return {
            "initialized": self.initialized,
            "registry": self.registry.status(),
            "api": self.api.status(),
        }

    @staticmethod
    def _to_bool(value: Any) -> bool:
        """Convert common Airtable boolean values to bool."""

        if isinstance(value, bool):
            return value

        if value is None:
            return False

        if isinstance(value, str):
            return value.strip().lower() in {
                "true",
                "yes",
                "1",
                "required",
            }

        if isinstance(value, (int, float)):
            return value != 0

        return False

    @staticmethod
    def _error(
        message: str,
        **details: Any,
    ) -> Dict[str, Any]:
        """Create a standard CVE error response."""

        response = {
            "success": False,
            "status": "error",
            "error": message,
        }

        response.update(details)

        return response


def self_test() -> bool:
    """Basic engine self-test."""

    engine = CVEEngine()

    assert engine.initialized is False

    status = engine.status()

    assert "registry" in status
    assert "api" in status

    return True


if __name__ == "__main__":
    print("CVE Engine self-test:", self_test())
