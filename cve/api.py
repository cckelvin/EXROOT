"""
EXROOT CVE API

The CVE API is the operational interface between the CVE engine
and the EXROOT runtime.

Architecture:

    CVE Command
         ↓
       Engine
         ↓
      CVE API
         ↓
      Runtime
         ↓
      Host OS

The API describes WHAT operation is being requested.
The runtime determines HOW that operation is performed.

Command-level confirmation belongs to the Commands registry,
not this file.
"""

from __future__ import annotations

from typing import Any, Callable

from runtime import filesystem
from runtime import network
from runtime import package
from runtime import process


# ============================================================
# API ERROR
# ============================================================

class CVEAPIError(Exception):
    """Raised when a CVE API operation cannot be completed."""


# ============================================================
# RUNTIME MODULES
# ============================================================

RUNTIME_MODULES = {
    "filesystem": filesystem,
    "network": network,
    "package": package,
    "process": process,
}


# ============================================================
# API CLASS
# ============================================================

class CVEAPI:
    """
    Operational CVE API.

    The engine can call:

        api.call("filesystem.mkdir", args, options)

    which routes to:

        runtime.filesystem.mkdir(...)
    """

    def __init__(self) -> None:

        self.functions: dict[
            str,
            Callable[..., Any]
        ] = {}

        self._register_runtime_functions()

    # ========================================================
    # REGISTER RUNTIME FUNCTIONS
    # ========================================================

    def _register_runtime_functions(self) -> None:
        """
        Register available runtime functions.

        This creates the operational mapping:

            filesystem.mkdir
                ↓
            runtime.filesystem.mkdir

        The full architecture registry can later provide
        additional mappings from Airtable.
        """

        self.register(
            "filesystem.mkdir",
            filesystem.mkdir,
        )

        self.register(
            "filesystem.readFile",
            filesystem.readFile,
        )

        self.register(
            "filesystem.writeFile",
            filesystem.writeFile,
        )

        self.register(
            "filesystem.delete",
            filesystem.delete,
        )

        self.register(
            "filesystem.copy",
            filesystem.copy,
        )

        self.register(
            "filesystem.move",
            filesystem.move,
        )

        self.register(
            "filesystem.stat",
            filesystem.stat,
        )

        self.register(
            "filesystem.exists",
            filesystem.exists,
        )

        self.register(
            "filesystem.list",
            filesystem.list,
        )

        self.register(
            "filesystem.cwd",
            filesystem.cwd,
        )

        self.register(
            "filesystem.chdir",
            filesystem.chdir,
        )

        self.register(
            "filesystem.head",
            filesystem.head,
        )

        self.register(
            "filesystem.tail",
            filesystem.tail,
        )

        self.register(
            "filesystem.checksum",
            filesystem.checksum,
        )

        self.register(
            "filesystem.watch",
            filesystem.watch,
        )

        self.register(
            "process.spawn",
            process.spawn,
        )

        self.register(
            "process.exec",
            process.exec,
        )

        self.register(
            "process.kill",
            process.kill,
        )

        self.register(
            "process.list",
            process.list,
        )

        self.register(
            "process.info",
            process.info,
        )

        self.register(
            "process.stdin",
            process.stdin,
        )

        self.register(
            "process.stdout",
            process.stdout,
        )

        self.register(
            "process.stderr",
            process.stderr,
        )

        self.register(
            "network.httpRequest",
            network.httpRequest,
        )

        self.register(
            "network.tcpConnect",
            network.tcpConnect,
        )

        self.register(
            "network.tcpListen",
            network.tcpListen,
        )

        self.register(
            "network.dnsLookup",
            network.dnsLookup,
        )

        self.register(
            "network.route",
            network.route,
        )

        self.register(
            "network.portInspect",
            network.portInspect,
        )

        self.register(
            "network.portClose",
            network.portClose,
        )

        self.register(
            "package.install",
            package.install,
        )

        self.register(
            "package.remove",
            package.remove,
        )

        self.register(
            "package.update",
            package.update,
        )

        self.register(
            "package.search",
            package.search,
        )

        self.register(
            "package.list",
            package.list,
        )

    # ========================================================
    # REGISTER
    # ========================================================

    def register(
        self,
        name: str,
        function: Callable[..., Any],
    ) -> None:
        """Register an API function."""

        if not name:
            raise CVEAPIError(
                "API function name cannot be empty."
            )

        if not callable(function):
            raise CVEAPIError(
                f"API target for '{name}' is not callable."
            )

        self.functions[name] = function

    # ========================================================
    # EXISTS
    # ========================================================

    def exists(
        self,
        name: str,
    ) -> bool:
        """Check whether an API function exists."""

        return name in self.functions

    # ========================================================
    # GET
    # ========================================================

    def get(
        self,
        name: str,
    ) -> Callable[..., Any] | None:
        """Return an API function."""

        return self.functions.get(name)

    # ========================================================
    # CALL
    # ========================================================

    def call(
        self,
        name: str,
        args: list[str] | None = None,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Execute an API function.

        Example:

            api.call(
                "filesystem.mkdir",
                ["project"],
                {}
            )
        """

        function = self.get(name)

        if function is None:

            return {
                "success": False,
                "error": (
                    f"Unknown CVE API function: {name}"
                ),
            }

        args = args or []
        options = options or {}

        try:

            result = function(
                args,
                options,
            )

            return {
                "success": True,
                "api": name,
                "result": result,
            }

        except Exception as error:

            return {
                "success": False,
                "api": name,
                "error": str(error),
            }

    # ========================================================
    # CALL RAW
    # ========================================================

    def call_raw(
        self,
        name: str,
        args: list[str] | None = None,
        options: dict[str, Any] | None = None,
    ) -> Any:
        """
        Execute an API function and return its raw runtime result.

        This is useful internally when another CVE component needs
        the runtime result directly.
        """

        function = self.get(name)

        if function is None:
            raise CVEAPIError(
                f"Unknown CVE API function: {name}"
            )

        return function(
            args or [],
            options or {},
        )

    # ========================================================
    # LIST FUNCTIONS
    # ========================================================

    def list_functions(self) -> list[str]:
        """Return registered API functions."""

        return sorted(
            self.functions.keys()
        )

    # ========================================================
    # API INFORMATION
    # ========================================================

    def info(
        self,
        name: str,
    ) -> dict[str, Any] | None:
        """Return information about an API function."""

        function = self.get(name)

        if function is None:
            return None

        return {
            "name": name,
            "module": function.__module__,
            "function": function.__name__,
            "available": True,
        }

    # ========================================================
    # STATUS
    # ========================================================

    def status(self) -> dict[str, Any]:

        return {
            "available": True,
            "function_count": len(
                self.functions
            ),
            "functions": self.list_functions(),
        }


# ============================================================
# DEFAULT API INSTANCE
# ============================================================

api = CVEAPI()


# ============================================================
# CONVENIENCE FUNCTION
# ============================================================

def call(
    name: str,
    args: list[str] | None = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Convenience wrapper around the default CVE API.
    """

    return api.call(
        name,
        args,
        options,
    )


# ============================================================
# API SELF-TEST
# ============================================================

def self_test() -> bool:
    """Run basic CVE API tests."""

    assert api.exists(
        "filesystem.mkdir"
    )

    assert api.exists(
        "filesystem.readFile"
    )

    assert api.exists(
        "process.exec"
    )

    assert api.exists(
        "network.httpRequest"
    )

    assert api.exists(
        "package.install"
    )

    assert not api.exists(
        "does.not.exist"
    )

    return True


# ============================================================
# MODULE TEST
# ============================================================

if __name__ == "__main__":

    print("EXROOT CVE API Test")
    print("-------------------")

    try:

        if self_test():
            print("API tests passed.")

        print()
        print(
            f"Registered API functions: "
            f"{len(api.functions)}"
        )

    except AssertionError:

        print("API tests failed.")

    except Exception as error:

        print(f"API error: {error}")
