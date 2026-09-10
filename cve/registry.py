"""EXROOT CVE Registry - offline-capable command map with optional Airtable."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

DEFAULT_BASE_ID = "appQurC5u0uMfyVp2"
COMMANDS_TABLE_ID = "tblQPYLJAXcRMfO0r"
API_FUNCTIONS_TABLE_ID = "tblqGqCGCNiftJAlD"
RUNTIME_FUNCTIONS_TABLE_ID = "tblVRVMsdr7bbunTR"

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

DEFAULT_COMMAND_MAP = {
    "mkdir": "filesystem.mkdir",
    "read": "filesystem.readFile",
    "write": "filesystem.writeFile",
    "rm": "filesystem.delete",
    "delete": "filesystem.delete",
    "cp": "filesystem.copy",
    "copy": "filesystem.copy",
    "mv": "filesystem.move",
    "move": "filesystem.move",
    "stat": "filesystem.stat",
    "exists": "filesystem.exists",
    "ls": "filesystem.list",
    "list": "filesystem.list",
    "pwd": "filesystem.cwd",
    "cwd": "filesystem.cwd",
    "cd": "filesystem.chdir",
    "chdir": "filesystem.chdir",
    "head": "filesystem.head",
    "tail": "filesystem.tail",
    "checksum": "filesystem.checksum",
    "exec": "process.exec",
    "spawn": "process.spawn",
    "kill": "process.kill",
    "ps": "process.list",
    "proc": "process.info",
    "http": "network.httpRequest",
    "dns": "network.dnsLookup",
    "route": "network.route",
    "port": "network.portInspect",
    "pkg-install": "package.install",
    "pkg-remove": "package.remove",
    "pkg-list": "package.list",
    "pkg-search": "package.search",
    "pkg-update": "package.update",
}


class RegistryError(Exception):
    pass


class CVERegistry:
    def __init__(self, base_id=None, token=None):
        self.base_id = base_id or os.getenv("EXROOT_AIRTABLE_BASE_ID") or DEFAULT_BASE_ID
        self.token = token or os.getenv("EXROOT_AIRTABLE_TOKEN") or os.getenv("AIRTABLE_TOKEN")
        self.commands = {}
        self.api_functions = {}
        self.runtime_functions = {}
        self.loaded = False

    def _airtable_request(self, table_id, offset=None):
        if not self.token:
            raise RegistryError("Airtable token is not configured. Set EXROOT_AIRTABLE_TOKEN.")
        url = f"https://api.airtable.com/v0/{self.base_id}/{table_id}"
        if offset:
            url += f"?offset={offset}"
        request = Request(url)
        request.add_header("Authorization", f"Bearer {self.token}")
        request.add_header("Content-Type", "application/json")
        try:
            with urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            raise RegistryError(f"Airtable HTTP error {error.code}: {body}") from error
        except URLError as error:
            raise RegistryError(f"Unable to connect to Airtable: {error}") from error

    def _load_table(self, table_id):
        records, offset = [], None
        while True:
            data = self._airtable_request(table_id, offset)
            records.extend(data.get("records", []))
            offset = data.get("offset")
            if not offset:
                break
        return records

    @staticmethod
    def _field(fields, field_id, default=None):
        return fields.get(field_id, default)

    def load_commands(self):
        records = self._load_table(COMMANDS_TABLE_ID)
        self.commands.clear()
        for record in records:
            fields = record.get("fields", {})
            name = self._field(fields, COMMAND_FIELDS["command"])
            if not name:
                continue
            name = str(name).strip().lower()
            self.commands[name] = {
                "id": record.get("id"),
                "command": name,
                "syntax": self._field(fields, COMMAND_FIELDS["syntax"]),
                "description": self._field(fields, COMMAND_FIELDS["description"]),
                "category": self._field(fields, COMMAND_FIELDS["category"]),
                "confirmation_required": self._field(fields, COMMAND_FIELDS["confirmation_required"], False),
                "confirmation_type": self._field(fields, COMMAND_FIELDS["confirmation_type"]),
                "confirmation_prompt": self._field(fields, COMMAND_FIELDS["confirmation_prompt"]),
                "risk_level": self._field(fields, COMMAND_FIELDS["risk_level"]),
                "reversible": self._field(fields, COMMAND_FIELDS["reversible"]),
                "requires_elevated_access": self._field(fields, COMMAND_FIELDS["requires_elevated_access"]),
                "host_access": self._field(fields, COMMAND_FIELDS["host_access"]),
                "status": self._field(fields, COMMAND_FIELDS["status"]),
                "notes": self._field(fields, COMMAND_FIELDS["notes"]),
                "_raw": fields,
            }
        return len(self.commands)

    def load_api_functions(self):
        records = self._load_table(API_FUNCTIONS_TABLE_ID)
        self.api_functions.clear()
        for record in records:
            fields = record.get("fields", {})
            name = self._field(fields, API_FIELDS["function"])
            if not name:
                continue
            name = str(name).strip()
            self.api_functions[name] = {
                "id": record.get("id"),
                "function": name,
                "description": self._field(fields, API_FIELDS["description"]),
                "input_schema": self._field(fields, API_FIELDS["input_schema"]),
                "output_schema": self._field(fields, API_FIELDS["output_schema"]),
                "status": self._field(fields, API_FIELDS["status"]),
                "notes": self._field(fields, API_FIELDS["notes"]),
                "_raw": fields,
            }
        return len(self.api_functions)

    def load_runtime_functions(self):
        records = self._load_table(RUNTIME_FUNCTIONS_TABLE_ID)
        self.runtime_functions.clear()
        for record in records:
            fields = record.get("fields", {})
            name = self._field(fields, RUNTIME_FIELDS["runtime_function"])
            if not name:
                continue
            name = str(name).strip()
            self.runtime_functions[name] = {
                "id": record.get("id"),
                "runtime_function": name,
                "description": self._field(fields, RUNTIME_FIELDS["description"]),
                "implementation_language": self._field(fields, RUNTIME_FIELDS["implementation_language"]),
                "status": self._field(fields, RUNTIME_FIELDS["status"]),
                "notes": self._field(fields, RUNTIME_FIELDS["notes"]),
                "host_primitive": self._field(fields, RUNTIME_FIELDS["host_primitive"]),
                "implementation_file": self._field(fields, RUNTIME_FIELDS["implementation_file"]),
                "_raw": fields,
            }
        return len(self.runtime_functions)

    def load_defaults(self):
        self.commands.clear()
        self.api_functions.clear()
        self.runtime_functions.clear()
        for command_name, api_name in DEFAULT_COMMAND_MAP.items():
            self.commands[command_name] = {
                "command": command_name,
                "status": "active",
                "confirmation_required": False,
                "api_function": api_name,
                "api": api_name,
                "_raw": {"API Function": api_name, "api": api_name},
            }
            self.api_functions[api_name] = {
                "function": api_name,
                "status": "active",
                "_raw": {"Runtime Function": api_name, "runtime_function": api_name},
            }
            self.runtime_functions[api_name] = {
                "runtime_function": api_name,
                "status": "active",
                "_raw": {},
            }
        self.loaded = True
        return {
            "commands": len(self.commands),
            "api_functions": len(self.api_functions),
            "runtime_functions": len(self.runtime_functions),
            "source": "local_defaults",
        }

    def load(self):
        if not self.token:
            return self.load_defaults()
        try:
            return {
                "commands": self.load_commands(),
                "api_functions": self.load_api_functions(),
                "runtime_functions": self.load_runtime_functions(),
                "source": "airtable",
            }
        except RegistryError as error:
            result = self.load_defaults()
            result["warning"] = str(error)
            result["source"] = "local_defaults_fallback"
            return result

    def get_command(self, command):
        if not command:
            return None
        return self.commands.get(command.strip().lower())

    def get_api_function(self, function):
        if not function:
            return None
        return self.api_functions.get(function.strip())

    def get_runtime_function(self, function):
        if not function:
            return None
        return self.runtime_functions.get(function.strip())

    def resolve_api_for_command(self, command):
        raw = command.get("_raw", {})
        candidates = [
            command.get("api_function"),
            command.get("api"),
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
            if isinstance(candidate, list) and candidate:
                candidate = candidate[0]
            if isinstance(candidate, dict):
                candidate = candidate.get("name") or candidate.get("id")
            result = self.get_api_function(str(candidate))
            if result:
                return result
        return None

    def resolve_runtime_for_api(self, api):
        raw = api.get("_raw", {})
        candidates = [
            raw.get("Runtime Function"),
            raw.get("runtime_function"),
            raw.get("Runtime"),
        ]
        for candidate in candidates:
            if not candidate:
                continue
            if isinstance(candidate, list) and candidate:
                candidate = candidate[0]
            if isinstance(candidate, dict):
                candidate = candidate.get("name") or candidate.get("id")
            result = self.get_runtime_function(str(candidate))
            if result:
                return result
        api_name = api.get("function")
        if api_name:
            direct = self.get_runtime_function(str(api_name))
            if direct:
                return direct
        return None

    def save_cache(self, path):
        cache_path = Path(path)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "commands": self.commands,
            "api_functions": self.api_functions,
            "runtime_functions": self.runtime_functions,
        }
        cache_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    def load_cache(self, path):
        cache_path = Path(path)
        if not cache_path.exists():
            return False
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            self.commands = data.get("commands", {})
            self.api_functions = data.get("api_functions", {})
            self.runtime_functions = data.get("runtime_functions", {})
            self.loaded = True
            return True
        except Exception:
            return False

    def status(self):
        return {
            "loaded": self.loaded,
            "commands": len(self.commands),
            "api_functions": len(self.api_functions),
            "runtime_functions": len(self.runtime_functions),
            "airtable_configured": bool(self.token),
        }
