"""
EXROOT CVE Registry

The registry is the bridge between the EXROOT architecture definition
and the running CVE system.

Airtable is the architecture source.

The registry loads:

    Commands
    API Functions
    Runtime Functions

The registry does NOT execute commands.

It only answers questions such as:

    Does this command exist?
    What API function does it use?
    What runtime function implements that API?
    What are the command's arguments?
    Does the command require confirmation?
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


# ============================================================
# EXROOT AIRTABLE CONFIGURATION
# ============================================================

DEFAULT_BASE_ID = "appQurC5u0uMfyVp2"

COMMANDS_TABLE_ID = "tblQPYLJAXcRMfO0r"
API_FUNCTIONS_TABLE_ID = "tblqGqCGCNiftJAlD"
RUNTIME_FUNCTIONS_TABLE_ID = "tblVRVMsdr7bbunTR"


# ============================================================
# FIELD IDS
# ============================================================

COMMAND_FIELDS = {
    "command": "fldq2v3zb3Gy2MrK4",
    "syntax": "fldeVlEPIUqcGegzB",
    "description": "fldDR0hSWClOvYq0S",
    "category": "fld6YvQTIjbb34x1O",
    "confirmation_required": "fldNnm0wEHFe67hvh",
    "confirmation_type": "fldSMdHT6JPE21FKq",
    "confirmation_prompt": "fldqbl7kW0zk8n9sk",
    "risk_level": "fldN2XFa49BLVMGPW",
    "reversible": "fldjAhAKF8zMJSG4z",
    "requires_elevated_access": "fldMGWJ4jMLDDTyBD",
    "host_access": "fldHecBxBxUGqPNgB",
    "status": "fldZ8kE2na0oaEwam",
    "notes": "fldfO6gKA5aDnqvYo",
}


API_FIELDS = {
    "function": "fldShs6dDpTjBV1ha",
    "description": "fldHiNHPKAQFlMDxe",
    "input_schema": "flda8T4BXPls76Zlq",
    "output_schema": "fldkMW3lhC5GZXuwy",
    "status": "fldWGeiA1UC0dABDD",
    "notes": "fldh4ydG9GZSOymNl",
}


RUNTIME_FIELDS = {
    "runtime_function": "fld5WYbzfWYbAq2Lg",
    "description": "fldmPQodgbyNjDUjd",
    "implementation_language": "fldJqgMBzdqtYwqnG",
    "status": "fldJ59VhxsJmUdqiR",
    "notes": "fldlBaow24HHno40Z",
    "host_primitive": "fldAYpcHjegfYuZOc",
    "implementation_file": "fldxOAOCSSwbxjTme",
}


# ============================================================
# REGISTRY ERROR
# ============================================================

class RegistryError(Exception):
    """Raised when the CVE registry cannot load or resolve data."""


# ============================================================
# REGISTRY
# ============================================================

class CVERegistry:
    """
    Registry for CVE architecture definitions.

    The registry can load data from Airtable and keep an in-memory
    copy for fast command resolution.
    """

    def __init__(
        self,
        base_id: str | None = None,
        token: str | None = None,
    ) -> None:

        self.base_id = (
            base_id
            or os.getenv("EXROOT_AIRTABLE_BASE_ID")
            or DEFAULT_BASE_ID
        )

        self.token = (
            token
            or os.getenv("EXROOT_AIRTABLE_TOKEN")
            or os.getenv("AIRTABLE_TOKEN")
        )

        self.commands: dict[str, dict[str, Any]] = {}
        self.api_functions: dict[str, dict[str, Any]] = {}
        self.runtime_functions: dict[str, dict[str, Any]] = {}

        self.loaded = False

    # ========================================================
    # AIRTABLE REQUEST
    # ========================================================

    def _airtable_request(
        self,
        table_id: str,
        offset: str | None = None,
    ) -> dict[str, Any]:

        if not self.token:
            raise RegistryError(
                "Airtable token is not configured. "
                "Set EXROOT_AIRTABLE_TOKEN."
            )

        url = (
            f"https://api.airtable.com/v0/"
            f"{self.base_id}/{table_id}"
        )

        params = []

        if offset:
            params.append(
                f"offset={offset}"
            )

        if params:
            url += "?" + "&".join(params)

        request = Request(url)

        request.add_header(
            "Authorization",
            f"Bearer {self.token}",
        )

        request.add_header(
            "Content-Type",
            "application/json",
        )

        try:

            with urlopen(request, timeout=30) as response:
                data = response.read().decode("utf-8")

            return json.loads(data)

        except HTTPError as error:

            body = error.read().decode("utf-8", errors="replace")

            raise RegistryError(
                f"Airtable HTTP error {error.code}: {body}"
            ) from error

        except URLError as error:

            raise RegistryError(
                f"Unable to connect to Airtable: {error}"
            ) from error

    # ========================================================
    # LOAD TABLE
    # ========================================================

    def _load_table(
        self,
        table_id: str,
    ) -> list[dict[str, Any]]:

        records = []
        offset = None

        while True:

            data = self._airtable_request(
                table_id,
                offset,
            )

            records.extend(
                data.get("records", [])
            )

            offset = data.get("offset")

            if not offset:
                break

        return records

    # ========================================================
    # FIELD VALUE
    # ========================================================

    @staticmethod
    def _field(
        fields: dict[str, Any],
        field_id: str,
        default: Any = None,
    ) -> Any:

        return fields.get(field_id, default)

    # ========================================================
    # LOAD COMMANDS
    # ========================================================

    def load_commands(self) -> int:

        records = self._load_table(
            COMMANDS_TABLE_ID
        )

        self.commands.clear()

        for record in records:

            fields = record.get("fields", {})

            name = self._field(
                fields,
                COMMAND_FIELDS["command"],
            )

            if not name:
                continue

            name = str(name).strip().lower()

            self.commands[name] = {
                "id": record.get("id"),
                "command": name,

                "syntax": self._field(
                    fields,
                    COMMAND_FIELDS["syntax"],
                ),

                "description": self._field(
                    fields,
                    COMMAND_FIELDS["description"],
                ),

                "category": self._field(
                    fields,
                    COMMAND_FIELDS["category"],
                ),

                # Command table is the authoritative source
                # for confirmation policy.
                "confirmation_required": self._field(
                    fields,
                    COMMAND_FIELDS["confirmation_required"],
                    False,
                ),

                "confirmation_type": self._field(
                    fields,
                    COMMAND_FIELDS["confirmation_type"],
                ),

                "confirmation_prompt": self._field(
                    fields,
                    COMMAND_FIELDS["confirmation_prompt"],
                ),

                "risk_level": self._field(
                    fields,
                    COMMAND_FIELDS["risk_level"],
                ),

                "reversible": self._field(
                    fields,
                    COMMAND_FIELDS["reversible"],
                ),

                "requires_elevated_access": self._field(
                    fields,
                    COMMAND_FIELDS["requires_elevated_access"],
                ),

                "host_access": self._field(
                    fields,
                    COMMAND_FIELDS["host_access"],
                ),

                "status": self._field(
                    fields,
                    COMMAND_FIELDS["status"],
                ),

                "notes": self._field(
                    fields,
                    COMMAND_FIELDS["notes"],
                ),

                # Preserve the original Airtable fields so future
                # mappings can be added without rewriting the loader.
                "_raw": fields,
            }

        return len(self.commands)

    # ========================================================
    # LOAD API FUNCTIONS
    # ========================================================

    def load_api_functions(self) -> int:

        records = self._load_table(
            API_FUNCTIONS_TABLE_ID
        )

        self.api_functions.clear()

        for record in records:

            fields = record.get("fields", {})

            name = self._field(
                fields,
                API_FIELDS["function"],
            )

            if not name:
                continue

            name = str(name).strip()

            self.api_functions[name] = {
                "id": record.get("id"),
                "function": name,

                "description": self._field(
                    fields,
                    API_FIELDS["description"],
                ),

                "input_schema": self._field(
                    fields,
                    API_FIELDS["input_schema"],
                ),

                "output_schema": self._field(
                    fields,
                    API_FIELDS["output_schema"],
                ),

                "status": self._field(
                    fields,
                    API_FIELDS["status"],
                ),

                "notes": self._field(
                    fields,
                    API_FIELDS["notes"],
                ),

                "_raw": fields,
            }

        return len(self.api_functions)

    # ========================================================
    # LOAD RUNTIME FUNCTIONS
    # ========================================================

    def load_runtime_functions(self) -> int:

        records = self._load_table(
            RUNTIME_FUNCTIONS_TABLE_ID
        )

        self.runtime_functions.clear()

        for record in records:

            fields = record.get("fields", {})

            name = self._field(
                fields,
                RUNTIME_FIELDS["runtime_function"],
            )

            if not name:
                continue

            name = str(name).strip()

            self.runtime_functions[name] = {
                "id": record.get("id"),
                "runtime_function": name,

                "description": self._field(
                    fields,
                    RUNTIME_FIELDS["description"],
                ),

                "implementation_language": self._field(
                    fields,
                    RUNTIME_FIELDS["implementation_language"],
                ),

                "status": self._field(
                    fields,
                    RUNTIME_FIELDS["status"],
                ),

                "notes": self._field(
                    fields,
                    RUNTIME_FIELDS["notes"],
                ),

                "host_primitive": self._field(
                    fields,
                    RUNTIME_FIELDS["host_primitive"],
                ),

                "implementation_file": self._field(
                    fields,
                    RUNTIME_FIELDS["implementation_file"],
                ),

                "_raw": fields,
            }

        return len(self.runtime_functions)

    # ========================================================
    # LOAD EVERYTHING
    # ========================================================

    def load(self) -> dict[str, int]:

        command_count = self.load_commands()
        api_count = self.load_api_functions()
        runtime_count = self.load_runtime_functions()

        self.loaded = True

        return {
            "commands": command_count,
            "api_functions": api_count,
            "runtime_functions": runtime_count,
        }

    # ========================================================
    # COMMAND LOOKUP
    # ========================================================

    def get_command(
        self,
        command: str,
    ) -> dict[str, Any] | None:

        if not command:
            return None

        return self.commands.get(
            command.strip().lower()
        )

    # ========================================================
    # API LOOKUP
    # ========================================================

    def get_api_function(
        self,
        function: str,
    ) -> dict[str, Any] | None:

        if not function:
            return None

        return self.api_functions.get(
            function.strip()
        )

    # ========================================================
    # RUNTIME LOOKUP
    # ========================================================

    def get_runtime_function(
        self,
        function: str,
    ) -> dict[str, Any] | None:

        if not function:
            return None

        return self.runtime_functions.get(
            function.strip()
        )

    # ========================================================
    # COMMAND → API MAPPING
    # ========================================================

    def resolve_api_for_command(
        self,
        command: dict[str, Any],
    ) -> dict[str, Any] | None:

        raw = command.get("_raw", {})

        # Try common possible field names.
        candidates = [
            raw.get("API Function"),
            raw.get("CVE API Function"),
            raw.get("API"),
            raw.get("api"),
            raw.get("api_function"),
            raw.get("API Function ID"),
        ]

        for candidate in candidates:

            if not candidate:
                continue

            if isinstance(candidate, list):

                if candidate:
                    candidate = candidate[0]

            if isinstance(candidate, dict):

                candidate = (
                    candidate.get("name")
                    or candidate.get("id")
                )

            result = self.get_api_function(
                str(candidate)
            )

            if result:
                return result

        return None

    # ========================================================
    # API → RUNTIME MAPPING
    # ========================================================

    def resolve_runtime_for_api(
        self,
        api: dict[str, Any],
    ) -> dict[str, Any] | None:

        raw = api.get("_raw", {})

        candidates = [
            raw.get("Runtime Function"),
            raw.get("runtime_function"),
            raw.get("Runtime"),
        ]

        for candidate in candidates:

            if not candidate:
                continue

            if isinstance(candidate, list):

                if candidate:
                    candidate = candidate[0]

            if isinstance(candidate, dict):

                candidate = (
                    candidate.get("name")
                    or candidate.get("id")
                )

            result = self.get_runtime_function(
                str(candidate)
            )

            if result:
                return result

        # If the API and runtime use matching names,
        # try a direct mapping.
        api_name = api.get("function")

        if api_name:

            direct = self.get_runtime_function(
                str(api_name)
            )

            if direct:
                return direct

        return None

    # ========================================================
    # CACHE
    # ========================================================

    def save_cache(
        self,
        path: str | Path,
    ) -> None:

        cache_path = Path(path)

        cache_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        data = {
            "commands": self.commands,
            "api_functions": self.api_functions,
            "runtime_functions": self.runtime_functions,
        }

        cache_path.write_text(
            json.dumps(
                data,
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )

    # ========================================================
    # LOAD CACHE
    # ========================================================

    def load_cache(
        self,
        path: str | Path,
    ) -> bool:

        cache_path = Path(path)

        if not cache_path.exists():
            return False

        try:

            data = json.loads(
                cache_path.read_text(
                    encoding="utf-8"
                )
            )

            self.commands = data.get(
                "commands",
                {},
            )

            self.api_functions = data.get(
                "api_functions",
                {},
            )

            self.runtime_functions = data.get(
                "runtime_functions",
                {},
            )

            self.loaded = True

            return True

        except Exception:
            return False

    # ========================================================
    # STATUS
    # ========================================================

    def status(self) -> dict[str, Any]:

        return {
            "loaded": self.loaded,
            "commands": len(self.commands),
            "api_functions": len(self.api_functions),
            "runtime_functions": len(
                self.runtime_functions
            ),
            "airtable_configured": bool(
                self.token
            ),
        }
