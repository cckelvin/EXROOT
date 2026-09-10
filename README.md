# EXROOT

A terminal-style shell and runtime for structured host operations.

EXROOT exposes filesystem, process, network, and package operations through a
`cve <command> ...` interface. Commands are resolved by a registry (Airtable
when configured, otherwise a built-in local map) and executed through a CVE
API that calls into the Python runtime modules.

## Architecture

```
User
  ↓
CVE Shell (main.py)
  ↓
CVE Parser
  ↓
CVE Engine
  ↓
CVE API
  ↓
Runtime (filesystem / process / network / package)
  ↓
Host Operating System
```

`maple/` is reserved for a future layer that can analyze terminal output and
generate CVE commands.

## Requirements

- Python 3.10+
- No third-party packages required for core shell + runtime

Optional:

- `EXROOT_AIRTABLE_TOKEN` – load command/API/runtime definitions from Airtable
- `EXROOT_AIRTABLE_BASE_ID` – override the default Airtable base

Without an Airtable token, EXROOT uses a built-in local command map so the
shell remains usable offline.

## Quick start

```bash
git clone https://github.com/cckelvin/EXROOT.git
cd EXROOT
python3 main.py
```

Interactive prompt:

```text
exroot> help
exroot> cve pwd
exroot> cve mkdir /tmp/demo
exroot> cve ls /tmp
exroot> cve read /etc/hostname
exroot> exit
```

Single-command mode:

```bash
python3 main.py "cve mkdir /tmp/demo"
python3 main.py "cve ls /tmp"
python3 main.py --version
```

## Built-in shell commands

| Command   | Description                |
|-----------|----------------------------|
| `help`    | Show help                  |
| `version` | Show EXROOT version        |
| `system`  | Host system information    |
| `clear`   | Clear the terminal         |
| `exit`    | Quit                       |

CVE commands must start with `cve`, for example:

```text
cve mkdir project
cve ls .
cve pwd
cve cd /tmp
cve read file.txt
cve write file.txt
cve rm path
cve cp src dst
cve mv src dst
cve stat path
cve exec echo hello
cve ps
cve http https://example.com
```

## Project layout

```text
EXROOT/
├── main.py              # Shell entry point
├── cve/
│   ├── parser.py        # Command line → structured command
│   ├── engine.py        # Registry lookup + execution
│   ├── registry.py      # Airtable / local command map
│   └── api.py           # Operational API → runtime
├── runtime/
│   ├── filesystem.py
│   ├── process.py
│   ├── network.py
│   └── package.py
├── maple/               # Future higher-level agent layer
└── ui/
    └── terminal.html    # Browser terminal UI (prototype)
```

## Airtable (optional)

When `EXROOT_AIRTABLE_TOKEN` is set, the registry loads Commands, API
Functions, and Runtime Functions from the configured Airtable base. Field IDs
and table IDs are defined in `cve/registry.py`.

If Airtable is unavailable or the token is missing, EXROOT falls back to
`DEFAULT_COMMAND_MAP` in the same file.

## Status

Version `0.1.0` – early prototype. Core shell, parser, engine, API, and
runtime modules are wired; Maple and the HTML UI are incomplete.

## License

Add a license file if you intend to distribute this project.
