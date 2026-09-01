"""Local persistent configuration — one store shared by the GUI, the CLI and the MCP tools.

WHY: third-party API keys (VirusTotal, ThreatFox, …) were read from environment variables only, so
a key typed in the GUI died with the process and a key exported in a shell was invisible to the GUI.
This is the single place both sides read and write, so the product is configured *once* and survives
reboots — the same reason it also holds non-secret preferences.

    from eventhound_config import get_api_key          # tools/ on sys.path
    key = get_api_key("virustotal")

    python tools/eventhound_config.py list             # masked status of every service
    python tools/eventhound_config.py set virustotal   # prompts, never echoes the key
    python tools/eventhound_config.py unset virustotal
    python tools/eventhound_config.py get-setting allow_egress

WHERE (§9/§10): `data/config.json` — `data/` is the project's private, gitignored area, so secrets
land where client data already lives and can never reach the repo. `uninstall-macos.sh` does not
touch `data/`, so a reinstall finds its keys again. Override with `EVENTHOUND_CONFIG=<path>`.

PRECEDENCE: an environment variable always wins over the stored value. An explicit `VT_API_KEY=…`
in front of a command is an intentional one-off override, and it must not be silently ignored —
nor overwritten in the file.

SECURITY: the file is written 0600 via an atomic replace; keys are never logged, never printed in
full, and never returned in full by the GUI endpoint (only a masked hint). Stored keys are not
encrypted — an at-rest secret store would need a master password the product has no way to hold
offline; the honest boundary is a private, permission-restricted file, stated as such in the UI.
"""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

CONFIG_VERSION = 1

# Known third-party services. `env` is the variable that overrides the stored value; adding a
# service is one entry here plus its use at the call site — nothing else in the product changes.
SERVICES: dict[str, dict] = {
    "virustotal": {"env": "VT_API_KEY", "label": "VirusTotal",
                   "url": "https://www.virustotal.com/gui/my-apikey",
                   "note": "IP/domain/hash reputation. Free tier: 4 lookups/min."},
    "threatfox": {"env": "THREATFOX_API_KEY", "label": "ThreatFox (abuse.ch)",
                  "url": "https://auth.abuse.ch/",
                  "note": "IOC lookups. Free account, Auth-Key header."},
    "shodan": {"env": "SHODAN_API_KEY", "label": "Shodan",
               "url": "https://account.shodan.io/",
               "note": "Optional: the keyless InternetDB endpoint already covers public IPs."},
}

# Non-secret preferences the product remembers between runs. Value = default.
SETTINGS_DEFAULTS: dict[str, object] = {
    "allow_egress": False,          # §7: outbound lookups stay opt-in, even when a key is stored
    "llm_model": "",                # empty = whatever EVENTHOUND_LLM_MODEL / the engine default says
}


def config_path() -> Path:
    """Where the store lives. `EVENTHOUND_CONFIG` overrides it (tests, or a shared location)."""
    override = os.environ.get("EVENTHOUND_CONFIG")
    if override:
        return Path(override).expanduser()
    return Path(__file__).resolve().parents[1] / "data" / "config.json"


def load() -> dict:
    """Read the store. A missing or corrupt file is not fatal: the product must still run."""
    path = config_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": CONFIG_VERSION, "api_keys": {}, "settings": {}}
    if not isinstance(data, dict):
        return {"version": CONFIG_VERSION, "api_keys": {}, "settings": {}}
    data.setdefault("version", CONFIG_VERSION)
    data.setdefault("api_keys", {})
    data.setdefault("settings", {})
    return data


def save(data: dict) -> Path:
    """Write the store 0600, atomically (temp file + replace): a crash mid-write must not leave a
    truncated config, and the file must never be world-readable — it holds secrets."""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)      # 0600 before it becomes visible under its name
    os.replace(tmp, path)
    return path


# ── API keys ─────────────────────────────────────────────────────────────────────────────
def get_api_key(service: str) -> str | None:
    """Key for a service: environment first (explicit override), then the stored value."""
    svc = SERVICES.get(service)
    if svc:
        env = os.environ.get(svc["env"], "").strip()
        if env:
            return env
    val = str(load()["api_keys"].get(service, "")).strip()
    return val or None


def set_api_key(service: str, value: str) -> Path:
    """Store a key. An empty value clears it (same as unset)."""
    if service not in SERVICES:
        raise ValueError(f"unknown service {service!r} (known: {', '.join(sorted(SERVICES))})")
    data = load()
    value = (value or "").strip()
    if value:
        data["api_keys"][service] = value
    else:
        data["api_keys"].pop(service, None)
    return save(data)


def unset_api_key(service: str) -> Path:
    return set_api_key(service, "")


def mask(value: str | None) -> str:
    """`…c0ffee` — enough to recognize which key is stored, not enough to use it."""
    v = (value or "").strip()
    if not v:
        return ""
    return "…" + v[-4:] if len(v) > 4 else "…"


def status() -> list[dict]:
    """Masked status of every known service — what the GUI and the CLI both display.

    Never contains a usable key. `source` says where the active value came from, because
    "I saved it in the GUI but an env var is winning" is otherwise invisible and confusing."""
    stored = load()["api_keys"]
    out = []
    for name, svc in SERVICES.items():
        env_val = os.environ.get(svc["env"], "").strip()
        stored_val = str(stored.get(name, "")).strip()
        active = env_val or stored_val
        out.append({
            "service": name,
            "label": svc["label"],
            "env_var": svc["env"],
            "url": svc["url"],
            "note": svc["note"],
            "configured": bool(active),
            "source": "environment" if env_val else ("config" if stored_val else ""),
            "hint": mask(active),
            "overridden_by_env": bool(env_val and stored_val and env_val != stored_val),
        })
    return out


# ── non-secret settings ──────────────────────────────────────────────────────────────────
def get_setting(name: str, default=None):
    if name not in SETTINGS_DEFAULTS and default is None:
        raise ValueError(f"unknown setting {name!r} (known: {', '.join(sorted(SETTINGS_DEFAULTS))})")
    return load()["settings"].get(name, SETTINGS_DEFAULTS.get(name, default))


def set_setting(name: str, value) -> Path:
    if name not in SETTINGS_DEFAULTS:
        raise ValueError(f"unknown setting {name!r} (known: {', '.join(sorted(SETTINGS_DEFAULTS))})")
    data = load()
    data["settings"][name] = value
    return save(data)


def settings() -> dict:
    """Effective settings: defaults overlaid with what is stored."""
    return {**SETTINGS_DEFAULTS, **load()["settings"]}


# ── CLI ──────────────────────────────────────────────────────────────────────────────────
def _cli(argv: list[str]) -> int:
    cmd = argv[0] if argv else "list"
    if cmd in ("-h", "--help"):
        print(__doc__.strip().split("\n\n")[2])
        return 0
    if cmd == "list":
        print(f"config: {config_path()}")
        for s in status():
            state = f"{s['hint']} (from {s['source']})" if s["configured"] else "not configured"
            flag = "  ! env var overrides the stored key" if s["overridden_by_env"] else ""
            print(f"  {s['label']:<22} {state}{flag}")
        print("settings:")
        for k, v in sorted(settings().items()):
            print(f"  {k:<22} {v!r}")
        return 0
    if cmd == "set":
        if len(argv) < 2:
            print("usage: set <service> [key]   (omit the key to be prompted without echo)")
            return 1
        service = argv[1]
        if service not in SERVICES:
            print(f"unknown service {service!r} (known: {', '.join(sorted(SERVICES))})")
            return 1
        # Prompt without echo by default: a key passed as an argument lands in the shell history.
        key = argv[2] if len(argv) > 2 else __import__("getpass").getpass(f"{SERVICES[service]['label']} key: ")
        path = set_api_key(service, key)
        print(f"{SERVICES[service]['label']}: {'stored' if key.strip() else 'cleared'} in {path} (0600)")
        return 0
    if cmd == "unset":
        if len(argv) < 2:
            print("usage: unset <service>")
            return 1
        unset_api_key(argv[1])
        print(f"{argv[1]}: cleared")
        return 0
    if cmd == "get-setting":
        if len(argv) < 2:
            print("usage: get-setting <name>")
            return 1
        print(get_setting(argv[1]))
        return 0
    if cmd == "set-setting":
        if len(argv) < 3:
            print("usage: set-setting <name> <value>   (true/false/number/text)")
            return 1
        raw = argv[2]
        val: object = raw
        if raw.lower() in ("true", "false"):
            val = raw.lower() == "true"
        elif raw.isdigit():
            val = int(raw)
        set_setting(argv[1], val)
        print(f"{argv[1]} = {val!r}")
        return 0
    print(f"unknown command {cmd!r} — use: list | set | unset | get-setting | set-setting")
    return 1


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
