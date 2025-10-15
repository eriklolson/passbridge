#!/usr/bin/env python3
"""
passbridge.py
Temporary secrets (JSON/YAML/CSV) -> pass bridge.

Commands:
  create   [-card | -logins] [--force]
    - Default: create JSON file at SECRETS_PATH and open in Sublime (subl).
    - -card:   copy ./templates/cards.json  -> SECRETS_PATH
    - -logins: copy ./templates/logins.json -> SECRETS_PATH

  topass    [--force]
    - Detects format of SECRETS_PATH (JSON / YAML / CSV) and imports to pass:
        * JSON logins: {entry, username, password, url, notes}
        * JSON cards:  {entry, card_no, name, exp, cvc, issuer, notes}
        * YAML (list of maps) with same keys as above
        * CSV header: entry,password,username,url,notes

  remove
    - Securely shred the secrets file at SECRETS_PATH

Config resolution priority (highest → lowest):
  1) .env variables in the project root (same dir as this script)
        SECRETS_PATH=~/.secrets.json
        TEMPLATES_PATH=~/Workspace/secretsbridge/templates
        PASSBRIDGE_CONFIG=~/custom/passbridge.yml   (optional)
  2) config.yml (either PASSBRIDGE_CONFIG if set, or ./config.yml, or ~/.config/passbridge/config.yml)
        secrets_path: "~/.secrets.json"
        templates_path: "~/Workspace/secretsbridge/templates"
  3) Defaults:
        SECRETS_PATH: ~/.secrets.json
        TEMPLATES_PATH: ./templates
"""

import argparse
import csv
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from secrets import token_bytes

# Optional YAML support
try:
    import yaml  # PyYAML
except Exception:
    yaml = None

# ---------- .env loader ----------
def load_dotenv(dotenv_path: Path):
    if not dotenv_path.exists():
        return
    try:
        for line in dotenv_path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            os.environ[k.strip()] = v.strip()
    except Exception as e:
        print(f"Warning: failed to parse .env: {e}", file=sys.stderr)

# ---------- Paths & config discovery ----------
SCRIPT_DIR = Path(__file__).resolve().parent
load_dotenv(SCRIPT_DIR / ".env")  # load .env first (may define PASSBRIDGE_CONFIG)

def _minimal_yaml_like_parse(text: str) -> dict:
    cfg = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or ":" not in s:
            continue
        k, v = s.split(":", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        cfg[k] = v
    return cfg

def load_config() -> dict:
    # Allow env to point explicitly at a config file
    cfg_env_path = os.getenv("PASSBRIDGE_CONFIG")
    candidates = []
    if cfg_env_path:
        candidates.append(Path(cfg_env_path).expanduser())
    candidates += [
        SCRIPT_DIR / "config.yml",
        Path("~/.config/passbridge/config.yml").expanduser(),
    ]
    for p in candidates:
        if p.exists():
            try:
                text = p.read_text(encoding="utf-8")
                if yaml is not None:
                    return yaml.safe_load(text) or {}
                return _minimal_yaml_like_parse(text)
            except Exception as e:
                print(f"Warning: failed to parse config {p}: {e}", file=sys.stderr)
                return {}
    return {}

CONFIG = load_config()

# Priority resolution: .env → config.yml → defaults
SECRETS_PATH = Path(
    os.getenv("SECRETS_PATH") or CONFIG.get("secrets_path") or "~/.secrets.json"
).expanduser()

TEMPLATE_DIR = Path(
    os.getenv("TEMPLATES_PATH") or CONFIG.get("templates_path") or (SCRIPT_DIR / "templates")
).expanduser()

# ---------- helpers ----------
def require_cmd(cmd: str):
    if shutil.which(cmd) is None:
        print(f"Error: '{cmd}' command not found in PATH.", file=sys.stderr)
        sys.exit(1)

def ensure_perm_user_only(path: Path):
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass  # best-effort only

def open_in_sublime(path: Path):
    require_cmd("subl")
    subprocess.run(["subl", str(path)], check=False)

def build_pass_body(secret: str, meta: dict) -> str:
    lines = [str(secret).strip()]
    for k, v in meta.items():
        if v is None:
            continue
        s = str(v).strip()
        if s:
            lines.append(f"{k}: {s}")
    return "\n".join(lines) + "\n"

def pass_insert(entry_path: str, content: str, force: bool):
    cmd = ["pass", "insert", "-m"]
    if force:
        cmd.append("-f")
    cmd.append(entry_path)
    try:
        subprocess.run(cmd, input=content, text=True, check=True)
        print(f"Added: {entry_path}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to add '{entry_path}': {e}", file=sys.stderr)

def detect_format(path: Path) -> str:
    """
    Returns 'json' | 'yaml' | 'csv'
    Uses file extension first; falls back to content sniff.
    """
    ext = path.suffix.lower()
    if ext == ".json":
        return "json"
    if ext in {".yml", ".yaml"}:
        return "yaml"
    if ext == ".csv":
        return "csv"
    try:
        with path.open("r", encoding="utf-8") as f:
            head = f.read(4096).lstrip()
        if head.startswith("{") or head.startswith("["):
            return "json"
        if head.startswith("---") or (":" in head.splitlines()[0] if head else False):
            return "yaml" if yaml else "csv"
    except Exception:
        pass
    return "csv"

# ---------- create ----------
def cmd_create(args):
    if SECRETS_PATH.exists() and not args.force:
        print(f"{SECRETS_PATH} already exists. Use --force to overwrite.")
        sys.exit(1)

    SECRETS_PATH.parent.mkdir(parents=True, exist_ok=True)

    # If a template flag is used, copy from templates dir.
    if args.card or args.logins:
        src = TEMPLATE_DIR / ("cards.json" if args.card else "logins.json")
        if not src.exists():
            # Auto-create minimal template if missing
            src.parent.mkdir(parents=True, exist_ok=True)
            if args.card:
                sample_cards = [
                    {"entry":"cards/example","card_no":"4111111111111111",
                     "name":"Your Name","exp":"01/30","cvc":"123","issuer":"Your Bank","notes":"example"}
                ]
                src.write_text(json.dumps(sample_cards, indent=2), encoding="utf-8")
            else:
                sample_logins = [
                    {"entry":"sites/example","username":"you","password":"change-me",
                     "url":"https://example.com","notes":"example"}
                ]
                src.write_text(json.dumps(sample_logins, indent=2), encoding="utf-8")
            print(f"Template not found; created minimal example at {src}")

        shutil.copyfile(src, SECRETS_PATH)
        ensure_perm_user_only(SECRETS_PATH)
        print(f"Copied {src} -> {SECRETS_PATH}")
        open_in_sublime(SECRETS_PATH)
        return

    # Default: create JSON structure for logins
    default_json = [
        {
            "entry": "sites/example",
            "username": "you",
            "password": "change-me",
            "url": "https://example.com",
            "notes": "example"
        }
    ]
    SECRETS_PATH.write_text(json.dumps(default_json, indent=2), encoding="utf-8")
    ensure_perm_user_only(SECRETS_PATH)
    print(f"Created default JSON secrets file at {SECRETS_PATH}")
    open_in_sublime(SECRETS_PATH)

# ---------- topass (CSV/JSON/YAML) ----------
def import_csv(path: Path, force: bool):
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        expected = ["entry", "password", "username", "url", "notes"]
        if reader.fieldnames is None or [h.lower() for h in reader.fieldnames] != expected:
            print(f"CSV must have header: {','.join(expected)}", file=sys.stderr)
            sys.exit(1)
        for row in reader:
            entry = (row.get("entry") or "").strip()
            pwd   = (row.get("password") or "").strip()
            if not entry or not pwd:
                continue
            meta = {
                "username": (row.get("username") or "").strip(),
                "url": (row.get("url") or "").strip(),
                "notes": (row.get("notes") or "").strip(),
            }
            pass_insert(entry, build_pass_body(pwd, meta), force)

def import_json(path: Path, force: bool):
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else [data]
    for item in items:
        if not isinstance(item, dict):
            continue
        entry = str(item.get("entry") or "").strip()
        if not entry:
            continue
        if "password" in item:
            secret = str(item.get("password") or "")
            meta = {"username": item.get("username"), "url": item.get("url"), "notes": item.get("notes")}
        elif "card_no" in item:
            secret = str(item.get("card_no") or "")
            meta = {"name": item.get("name"), "exp": item.get("exp"), "cvc": item.get("cvc"),
                    "issuer": item.get("issuer"), "notes": item.get("notes")}
        else:
            continue
        if not secret:
            continue
        pass_insert(entry, build_pass_body(secret, meta), force)

def import_yaml(path: Path, force: bool):
    if yaml is None:
        print("Error: YAML support not available. Install PyYAML (pip install pyyaml).", file=sys.stderr)
        sys.exit(1)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else [data]
    for item in items:
        if not isinstance(item, dict):
            continue
        entry = str(item.get("entry") or "").strip()
        if not entry:
            continue
        if "password" in item:
            secret = str(item.get("password") or "")
            meta = {"username": item.get("username"), "url": item.get("url"), "notes": item.get("notes")}
        elif "card_no" in item:
            secret = str(item.get("card_no") or "")
            meta = {"name": item.get("name"), "exp": item.get("exp"), "cvc": item.get("cvc"),
                    "issuer": item.get("issuer"), "notes": item.get("notes")}
        else:
            continue
        if not secret:
            continue
        pass_insert(entry, build_pass_body(secret, meta), force)

def cmd_topass(args):
    require_cmd("pass")
    if not SECRETS_PATH.exists():
        print(f"{SECRETS_PATH} not found. Run create first.", file=sys.stderr)
        sys.exit(1)
    fmt = detect_format(SECRETS_PATH)
    if fmt == "csv":
        import_csv(SECRETS_PATH, args.force)
    elif fmt == "json":
        import_json(SECRETS_PATH, args.force)
    elif fmt == "yaml":
        import_yaml(SECRETS_PATH, args.force)
    else:
        print(f"Unrecognized file format for {SECRETS_PATH}", file=sys.stderr)
        sys.exit(1)

# ---------- remove ----------
def secure_shred(path: Path):
    # Prefer GNU shred if available
    if shutil.which("shred"):
        try:
            subprocess.run(["shred", "-u", "-z", str(path)], check=True)
            print(f"Securely shredded (shred): {path}")
            return
        except subprocess.CalledProcessError:
            print("Warning: 'shred' failed; falling back to Python overwrite.", file=sys.stderr)
    # Python fallback
    try:
        size = path.stat().st_size
        with path.open("r+b", buffering=0) as f:
            for i in range(3):
                f.seek(0)
                remaining = size
                chunk = 1024 * 1024
                data_func = (lambda n: token_bytes(n)) if i != 1 else (lambda n: b"\x00" * n)
                while remaining > 0:
                    n = min(chunk, remaining)
                    f.write(data_func(n))
                    remaining -= n
                f.flush()
                os.fsync(f.fileno())
        path.unlink(missing_ok=False)
        print(f"Securely shredded (fallback): {path}")
    except FileNotFoundError:
        print(f"{path} does not exist.")
    except Exception as e:
        print(f"Error during secure shred: {e}", file=sys.stderr)
        sys.exit(1)

def cmd_remove(_args):
    if SECRETS_PATH.exists():
        secure_shred(SECRETS_PATH)
    else:
        print(f"{SECRETS_PATH} not found.")

# ---------- main ----------
def main():
    parser = argparse.ArgumentParser(description="Temporary secrets bridge to pass.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_create = sub.add_parser("create", help="Create secrets file or copy a template.")
    p_create.add_argument("--force", action="store_true")
    p_create.add_argument("-card", action="store_true", help="Copy ./templates/cards.json   -> SECRETS_PATH")
    p_create.add_argument("-logins", action="store_true", help="Copy ./templates/logins.json -> SECRETS_PATH")
    p_create.set_defaults(func=cmd_create)

    p_topass = sub.add_parser("topass", help="Import secrets into pass (JSON/YAML/CSV).")
    p_topass.add_argument("--force", action="store_true")
    p_topass.set_defaults(func=cmd_topass)

    p_remove = sub.add_parser("remove", help="Securely delete secrets file.")
    p_remove.set_defaults(func=cmd_remove)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
