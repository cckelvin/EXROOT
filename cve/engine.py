"""
EXROOT CVE Engine

The CVE engine is the execution coordinator.

Flow:

    Parsed command
          ↓
       Registry
          ↓
     Command definition
          ↓
       API function
          ↓
    Runtime function
          ↓
       Host system

The engine does NOT contain the command list.

The Commands table is the authoritative source for
command-level confirmation policy.
"""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path
from typing import Any

from cve.registry import CVERegistry, RegistryError


# ============================================================
# ENGINE ERROR
# ============================================================

class CVEEngineError(Exception):
    """Raised when CVE execution fails."""


# ============================================================
# CVE ENGINE
# ============================================================

class CVEEngine:

    def __init__(
        self,
        root_dir: str | Path | None = None,
        registry: CVERegistry | None = None,
    ) -> None:

        self.root_dir = Path(
            root_dir
            if root_dir is not None
            else Path(__file__).resolve().parent.parent
        )

        self.registry = (
            registry
            if registry is not None
            else CVERegistry()
        )

        self.loaded = False

    # ========================================================
    # START ENGINE
    # ========================================================

    def initialize(self) -> dict[str, int]:

        try:

            counts = self.registry.load()

            self.loaded = True

            return counts

        except RegistryError as error:

            raise CVEEngineError(
                f"Unable to initialize CVE registry: {error}"
            ) from error

    # ========================================================
    # ENSURE REGISTRY
    # ========================================================

    def _ensure_registry(self) -> None:

        if self.loaded:
            return

        # Try to load local cache first.
        cache_path = (
            self.root_dir
            / ".exroot"
            / "registry.json"
        )

        if self.registry.load_cache(cache_path):

            self.loaded = True
            return

        self.initialize()

        # Save the Airtable registry locally.
        try:
            self.registry.save_cache(
                cache_path
            )
        except Exception:
            pass

    # ========================================================
    # COMMAND EXECUTION
    # ========================================================

    def execute(
        self,
        parsed: dict[str, Any],
    ) -> dict[str, Any]:

        self._ensure_registry()

        if not isinstance(parsed, dict):

            return self.error(
                "Invalid parsed command."
            )

        command_name = parsed.get(
            "command"
        )

        if not command_name:

            return self.error(
                "No command specified."
            )

        # ----------------------------------------------------
        # Find command in registry
        # ----------------------------------------------------

        command = self.registry.get_command(
            command_name
        )

        if command is None:

            return self.error(
                f"Unknown CVE command: {command_name}"
            )

        # ----------------------------------------------------
        # Check command status
        # ----------------------------------------------------

        status = command.get("status")

        if isinstance(status, str):

            if status.lower() in {
                "disabled",
                "inactive",
                "deprecated",
            }:

                return self.error(
                    f"Command '{command_name}' "
                    f"is not active."
                )

        # ----------------------------------------------------
        # Confirmation
        # ----------------------------------------------------

        if self.requires_confirmation(command):

            confirmed = self.request_confirmation(
                command,
                parsed,
            )

            if not confirmed:

                return {
                    "success": False,
                    "cancelled": True,
                    "command": command_name,
                    "message": "Command cancelled.",
                }

        # ----------------------------------------------------
        # Resolve API
        # ----------------------------------------------------

        api = self.registry.resolve_api_for_command(
            command
        )

        if api is None:

            return self.error(
                f"No API function mapping found "
                f"for command '{command_name}'."
            )

        # ----------------------------------------------------
        # Resolve runtime
        # ----------------------------------------------------

        runtime = self.registry.resolve_runtime_for_api(
            api
        )

        if runtime is None:

            return self.error(
                f"No runtime mapping found "
                f"for API '{api.get('function')}'."
            )

        # ----------------------------------------------------
        # Execute runtime
        # ----------------------------------------------------

        return self.execute_runtime(
            parsed,
            command,
            api,
            runtime,
        )

    # ========================================================
    # CONFIRMATION POLICY
    # ========================================================

    @staticmethod
    def requires_confirmation(
        command: dict[str, Any],
    ) -> bool:

        value = command.get(
            "confirmation_required",
            False,
        )

        if isinstance(value, bool):
            return value

        if isinstance(value, str):

            return value.strip().lower() in {
                "true",
                "yes",
                "required",
                "1",
            }

        if isinstance(value, (int, float)):

            return bool(value)

        return False

    # ========================================================
    # REQUEST CONFIRMATION
    # ========================================================

    @staticmethod
    def request_confirmation(
        command: dict[str, Any],
        parsed: dict[str, Any],
    ) -> bool:

        prompt = command.get(
            "confirmation_prompt"
        )

        if not prompt:

            prompt = (
                f"Execute '{parsed.get('raw', '')}'?"
            )

        print()
        print(f"[CVE] {prompt}")
        print("Type 'yes' to continue.")

        try:
            answer = input(
                "Confirm: "
            ).strip().lower()

        except (KeyboardInterrupt, EOFError):

            print()
            return False

        return answer in {
            "yes",
            "y",
        }

    # ========================================================
    # RUNTIME EXECUTION
    # ========================================================

    def execute_runtime(
        self,
        parsed: dict[str, Any],
        command: dict[str, Any],
        api: dict[str, Any],
        runtime: dict[str, Any],
    ) -> dict[str, Any]:

        runtime_function = runtime.get(
            "runtime_function"
        )

        implementation_file = runtime.get(
            "implementation_file"
        )

        if not runtime_function:

            return self.error(
                "Runtime function has no name."
            )

        # ----------------------------------------------------
        # Locate implementation
        # ----------------------------------------------------

        module = self.load_runtime_module(
            runtime,
            implementation_file,
        )

        if module is None:

            return self.error(
                f"Runtime implementation not found "
                f"for '{runtime_function}'."
            )

        # ----------------------------------------------------
        # Determine function name
        # ----------------------------------------------------

        function_name = self.runtime_callable_name(
            runtime_function
        )

        function = getattr(
            module,
            function_name,
            None,
        )

        # Try generic "execute" implementation.
        if function is None:

            function = getattr(
                module,
                "execute",
                None,
            )

        if function is None:

            return self.error(
                f"Runtime module does not implement "
                f"'{function_name}'."
            )

        # ----------------------------------------------------
        # Build execution context
        # ----------------------------------------------------

        context = {
            "command": command,
            "api": api,
            "runtime": runtime,
            "parsed": parsed,
            "args": parsed.get(
                "args",
                [],
            ),
            "options": parsed.get(
                "options",
                {},
            ),
        }

        # ----------------------------------------------------
        # Call runtime function
        # ----------------------------------------------------

        try:

            result = self.call_runtime(
                function,
                context,
            )

            return {
                "success": True,
                "command": parsed.get("command"),
                "api": api.get("function"),
                "runtime": runtime_function,
                "result": result,
            }

        except Exception as error:

            return self.error(
                str(error),
                command=parsed.get("command"),
                api=api.get("function"),
                runtime=runtime_function,
            )

    # ========================================================
    # LOAD RUNTIME MODULE
    # ========================================================

    def load_runtime_module(
        self,
        runtime: dict[str, Any],
        implementation_file: Any,
    ):

        candidates = []

        if implementation_file:

            if isinstance(
                implementation_file,
                list,
            ):

                for item in implementation_file:

                    if isinstance(item, dict):
                        item = (
                            item.get("name")
                            or item.get("filename")
                        )

                    candidates.append(
                        str(item)
                    )

            else:

                candidates.append(
                    str(implementation_file)
                )

        runtime_name = runtime.get(
            "runtime_function"
        )

        if runtime_name:

            parts = runtime_name.split(".")

            if len(parts) >= 2:

                candidates.append(
                    "runtime."
                    + parts[1]
                )

        for candidate in candidates:

            candidate = candidate.replace(
                "\\",
                "/",
            )

            # ----------------------------------------------
            # Python module path
            # ----------------------------------------------

            if candidate.endswith(".py"):

                candidate = candidate[:-3]

            candidate = candidate.replace(
                "/",
                ".",
            )

            if candidate.startswith("."):
                candidate = candidate[1:]

            try:

                return importlib.import_module(
                    candidate
                )

            except ImportError:
                pass

        return None

    # ========================================================
    # RUNTIME CALLABLE NAME
    # ========================================================

    @staticmethod
    def runtime_callable_name(
        runtime_function: str,
    ) -> str:

        """
        Convert:

            runtime.filesystem.mkdir

        into:

            mkdir
        """

        return runtime_function.split(".")[-1]

    # ========================================================
    # CALL RUNTIME
    # ========================================================

    @staticmethod
    def call_runtime(
        function,
        context: dict[str, Any],
    ):

        """
        Call a runtime implementation.

        Runtime functions can eventually use either:

            function(context)

        or:

            function(args, options)

        The engine supports both patterns.
        """

        try:

            signature = inspect.signature(
                function
            )

            parameters = list(
                signature.parameters.values()
            )

        except (TypeError, ValueError):

            return function(context)

        # No parameters.
        if not parameters:

            return function()

        # One parameter.
        if len(parameters) == 1:

            return function(context)

        # Two or more parameters.
        return function(
            context["args"],
            context["options"],
        )

    # ========================================================
    # ERROR RESULT
    # ========================================================

    @staticmethod
    def error(
        message: str,
        **extra,
    ) -> dict[str, Any]:

        result = {
            "success": False,
            "error": message,
        }

        result.update(extra)

        return result

    # ========================================================
    # ENGINE STATUS
    # ========================================================

    def status(self) -> dict[str, Any]:

        return {
            "engine_loaded": self.loaded,
            **self.registry.status(),
        }
