
#!/usr/bin/env python3
import csv, json, os, shlex, subprocess, sys, time, logging
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------
# Logging setup
# ---------------------------
def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    if verbose and quiet:
        quiet = False
    level = logging.INFO
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
log = logging.getLogger(__name__)

# ---------------------------
# Subprocess helpers
# ---------------------------
def run(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def fail(msg: str, code: int = 1) -> None:
    log.error(msg)
    sys.exit(code)

def ensure_op_available() -> None:
    res = run(["op", "--version"])
    if res.returncode != 0:
        fail("1Password CLI `op` not found in PATH. Install it and try again.")
    log.debug("Detected 1Password CLI: %s", res.stdout.strip())

def op_cmd(args: List[str], session: Optional[str] = None) -> str:
    cmd = ["op"] + args
    if session:
        cmd += ["--session", session]
    log.debug("Running: %s", " ".join(shlex.quote(x) for x in cmd))
    res = run(cmd)
    if res.returncode != 0:
        fail(f"`op {' '.join(shlex.quote(a) for a in args)}` failed:\n{res.stderr}")
    return res.stdout

# ---------------------------
# Session handling
# ---------------------------
def discover_existing_session() -> Optional[str]:
    # Prefer account-scoped OP_SESSION_<shorthand>, fallback to OP_SESSION
    for k, v in os.environ.items():
        if k.startswith("OP_SESSION_") and v:
            return v.strip()
    tok = os.getenv("OP_SESSION")
    return tok.strip() if tok else None

def try_whoami(session: Optional[str]) -> bool:
    try:
        out = op_cmd(["whoami"], session)
        ok = bool(out.strip())
        log.debug("whoami (%s): %s", "with session" if session else "no session", "OK" if ok else "EMPTY")
        return ok
    except Exception as e:
        log.debug("whoami failed: %s", e)
        return False

def get_session_token(account: Optional[str]) -> Optional[str]:
    # 1) Existing env token
    existing = discover_existing_session()
    if existing:
        log.info("[*] Using existing OP_SESSION* token from environment.")
        if try_whoami(existing):
            return existing
        log.warning("[!] Existing OP_SESSION token appears invalid, will try fresh signin.")

    # 2) Try a generic signin (interactive)
    log.info("[*] Signing into 1Password...")
    try:
        token = op_cmd(["signin", "--raw"]).strip()
        if token:
            return token
        else:
            log.warning("[!] `op signin --raw` returned empty token.")
    except Exception as e:
        log.warning("[!] `op signin --raw` failed: %s", e)

    # 3) Try account-qualified (if provided)
    if account:
        log.info("[*] Attempting `op signin --account %s --raw`...", account)
        try:
            token = op_cmd(["signin", "--account", account, "--raw"]).strip()
            if token:
                return token
            else:
                log.warning("[!] Account-qualified signin returned empty token.")
        except Exception as e:
            log.warning("[!] Account-qualified signin failed: %s", e)

    # No token
    return None

# ---------------------------
# Extraction helpers
# ---------------------------
def first_url(item: Dict[str, Any]) -> Optional[str]:
    urls = item.get("urls") or []
    if isinstance(urls, list) and urls:
        href = urls[0].get("href")
        if href:
            return href
    if item.get("url"):
        return item.get("url")
    return None

def field_value(item: Dict[str, Any], predicate) -> Optional[str]:
    for f in (item.get("fields") or []):
        try:
            if predicate(f):
                val = f.get("value")
                if val is not None:
                    return val
        except Exception:
            continue
    return None

def extract_username(item: Dict[str, Any]) -> Optional[str]:
    return (
        field_value(item, lambda f: f.get("purpose") == "USERNAME")
        or field_value(item, lambda f: f.get("id") == "username")
        or field_value(item, lambda f: (f.get("label") or "").lower() == "username")
    )

def extract_password(item: Dict[str, Any]) -> Optional[str]:
    return (
        field_value(item, lambda f: f.get("purpose") == "PASSWORD")
        or field_value(item, lambda f: f.get("id") == "password")
        or field_value(item, lambda f: f.get("type") == "concealed")
        or field_value(item, lambda f: (f.get("label") or "").lower() in {"password", "passcode", "secret"})
    )

def to_tags(item: Dict[str, Any]) -> str:
    tags = item.get("tags") or []
    return ";".join(str(t) for t in tags) if isinstance(tags, list) else ""

# ---------------------------
# Export core
# ---------------------------
def export_passwords(
    out_file: str,
    only_login: bool = True,
    vault_filter: Optional[str] = None,
    account: Optional[str] = None,
) -> Tuple[int, int]:
    """
    Export passwords to CSV. Returns (vault_count, item_exported_count)
    """
    ensure_op_available()

    # Try to obtain a token; if not possible, rely on unlocked desktop app
    session = get_session_token(account)

    # If still no token, check if we can operate without session (desktop app unlocked)
    if session is None:
        log.info("[*] No session token available. Checking if the desktop app is unlocked...")
        if not try_whoami(None):
            fail(
                "Cannot obtain a session token and the 1Password app appears locked.\n"
                "Open and unlock the 1Password desktop app (CLI v2), or run `op account add` "
                "and then `op signin --raw` interactively."
            )
        else:
            log.info("[*] Proceeding without --session (desktop app appears unlocked).")

    def op_call(args: List[str]) -> str:
        # Prefer session if we have it; otherwise rely on unlocked app
        return op_cmd(args, session)

    # Vaults
    vaults = json.loads(op_call(["vault", "list", "--format", "json"]))
    if vault_filter:
        vaults = [v for v in vaults if v.get("name") == vault_filter or v.get("id") == vault_filter]
        if not vaults:
            fail(f"No vault matched filter: {vault_filter}")

    os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)
    total_items_exported = 0
    start = time.time()

    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["vault", "item_title", "username", "password", "url", "item_id", "category", "tags"])

        for v in vaults:
            vault_id = v.get("id")
            vault_name = v.get("name", vault_id)
            log.info("  [+] Vault: %s (%s)", vault_name, vault_id)

            items = json.loads(op_call(["item", "list", "--vault", vault_id, "--format", "json"]))
            log.info("      → %d item(s) listed.", len(items))

            processed = 0
            to_process = len(items)

            for it in items:
                category = (it.get("category") or "").upper()
                if only_login and category and category != "LOGIN":
                    processed += 1
                    if processed % 50 == 0 or processed == to_process:
                        log.debug("      Progress: %d/%d", processed, to_process)
                    continue

                item_id = it.get("id")
                item = json.loads(op_call(["item", "get", item_id, "--vault", vault_id, "--format", "json", "--reveal"]))

                title = item.get("title", "")
                username = extract_username(item) or ""
                password = extract_password(item) or ""
                url = first_url(item) or ""
                tags = to_tags(item)

                writer.writerow([vault_name, title, username, password, url, item_id, category, tags])

                processed += 1
                total_items_exported += 1

                if processed % 25 == 0 or processed == to_process:
                    log.info("      Progress: %d/%d (exported: %d)", processed, to_process, total_items_exported)

    elapsed = time.time() - start
    log.info("[*] Export complete in %.2f seconds.", elapsed)

    try:
        os.chmod(out_file, 0o600)
        log.info("[*] Set file permissions to 600 on: %s", out_file)
    except Exception as e:
        log.warning("[!] Could not set file permissions: %s", e)

    return (len(vaults), total_items_exported)

# ---------------------------
# CLI args
# ---------------------------
def parse_args(argv: List[str]) -> Dict[str, Any]:
    out_file = "./exports/passwords.csv"
    only_login = True
    vault_filter = None
    verbose = False
    quiet = False
    account = None

    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-o", "--out") and i + 1 < len(argv):
            out_file = argv[i + 1]; i += 2
        elif a in ("-v", "--vault") and i + 1 < len(argv):
            vault_filter = argv[i + 1]; i += 2
        elif a in ("-A", "--all-categories"):
            only_login = False; i += 1
        elif a in ("-V", "--verbose"):
            verbose = True; i += 1
        elif a in ("-q", "--quiet"):
            quiet = True; i += 1
        elif a in ("-a", "--account") and i + 1 < len(argv):
            account = argv[i + 1]; i += 2
        elif a in ("-h", "--help"):
            print(
                "Usage: export_passwords.py [--out PATH] [--vault NAME_OR_ID] [--all-categories] "
                "[--verbose|--quiet] [--account DOMAIN]\n"
                "  --out PATH           Output CSV path (default: ./exports/passwords.csv)\n"
                "  --vault NAME_OR_ID   Limit to a specific vault (by name or id)\n"
                "  --all-categories     Export passwords from all item categories (default: LOGIN only)\n"
                "  --verbose            More detailed logs (DEBUG)\n"
                "  --quiet              Minimal logs (WARNING)\n"
                "  --account DOMAIN     Your 1Password domain (e.g., myteam.1password.com)\n"
            ); sys.exit(0)
        else:
            print(f"[!] Unknown argument: {a}"); sys.exit(2)
    return {
        "out_file": out_file,
        "only_login": only_login,
        "vault_filter": vault_filter,
        "verbose": verbose,
        "quiet": quiet,
        "account": account,
    }

def main():
    args = parse_args(sys.argv[1:])
    setup_logging(verbose=args.pop("verbose"), quiet=args.pop("quiet"))
    vaults_count, exported = export_passwords(**args)
    log.info("[*] Summary: vaults=%d, items_exported=%d, output=%s",
             vaults_count, exported, args["out_file"])

if __name__ == "__main__":
    main()
