"""
Vertigo CLI — cloud ML edition.
"""

import json
import logging
import os
import sys
import argparse

from . import api
from .cloud_client import CloudClient, CloudError, get_client

# ── Logging setup ─────────────────────────────────────────────────────────────

_LOG_FORMAT = "%(asctime)s  %(levelname)-8s  %(name)-40s  %(message)s"
_LOG_DATE   = "%H:%M:%S"


def _configure_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.WARNING
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATE))
    root = logging.getLogger("vertigo")
    root.setLevel(level)
    root.addHandler(handler)
    root.propagate = False


logger = logging.getLogger("vertigo.cli")

# ── Serialisation helper ──────────────────────────────────────────────────────

def _to_serializable(obj):
    if isinstance(obj, list):
        return [_to_serializable(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _to_serializable(v) for k, v in obj.items()}
    if hasattr(obj, "__dict__"):
        return {k: _to_serializable(v) for k, v in obj.__dict__.items()}
    return obj

# ── Auth / licence helpers ────────────────────────────────────────────────────

def _get_api_key() -> str | None:
    return os.environ.get("XAHICO_VERTIGO_API_KEY") or None


def _require_api_key(operation: str) -> str:
    key = _get_api_key()
    if not key:
        print(
            f"\n[vertigo] ERROR: '{operation}' requires a valid XAHICO API key.\n"
            f"  Set the environment variable XAHICO_VERTIGO_API_KEY and retry.\n"
            f"  To obtain a key visit https://xahico.com/vertigo\n",
            file=sys.stderr,
        )
        sys.exit(2)
    return key


def _validate_license(client: CloudClient, operation: str) -> None:
    logger.debug("license_check  operation=%r", operation)
    try:
        result = client.validate_license()
        if not result.get("valid", False):
            reason = result.get("reason", "unknown")
            print(
                f"\n[vertigo] ERROR: Licence validation failed for '{operation}': {reason}\n"
                f"  Visit https://xahico.com/vertigo to renew your licence.\n",
                file=sys.stderr,
            )
            sys.exit(2)
        logger.debug(
            "license_valid  plan=%r  expires_at=%r",
            result.get("plan", "unknown"),
            result.get("expires_at", "unknown"),
        )
    except CloudError as exc:
        print(
            f"\n[vertigo] ERROR: Could not reach the XAHICO licence server: {exc}\n"
            f"  Check your network connection and try again.\n",
            file=sys.stderr,
        )
        sys.exit(2)

# ── Output helper ─────────────────────────────────────────────────────────────

def _write_output(data, output_path: str | None, label: str, silent: bool) -> None:
    serialised = json.dumps(_to_serializable(data), indent=2)
    if output_path:
        abs_path = os.path.abspath(output_path)
        with open(abs_path, "w") as fh:
            fh.write(serialised)
        logger.debug("output_written  label=%r  path=%r  bytes=%d", label, abs_path, len(serialised))
    else:
        if not silent:
            print(serialised)

# ── Entry point ───────────────────────────────────────────────────────────────

def __main__():
    parser = argparse.ArgumentParser(
        prog="vertigo",
        description="Vertigo Web Application Security Auditing & Testing Suite",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Enable structured debug logging to stderr",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── auth ──────────────────────────────────────────────────────────────────
    sp = subparsers.add_parser("auth", help="Authenticate to a target web host")
    sp.add_argument("target", type=str)
    sp.add_argument("--debug", action="store_true", default=False)
    sp.add_argument("-entry", type=str, default="/", help="Entry point path (default: /)")
    sp.add_argument("-headless", dest="headless", default=True, action="store_true")
    sp.add_argument("-no-headless", dest="headless", action="store_false")
    sp.add_argument("-output", type=str, default=None)
    sp.add_argument("-password", type=str, default="")
    sp.add_argument("-silent", default=False, action="store_true")
    sp.add_argument("-username", type=str)

    # ── fingerprint ───────────────────────────────────────────────────────────
    sp = subparsers.add_parser("fingerprint", help="Fingerprint a target web host")
    sp.add_argument("target", type=str)
    sp.add_argument("--debug", action="store_true", default=False)
    sp.add_argument("-concurrency", type=int, default=3)
    sp.add_argument("-entry", type=str, default="/")
    sp.add_argument("-depth", type=int, default=3)
    sp.add_argument("-headless", dest="headless", default=True, action="store_true")
    sp.add_argument("-limit", type=int, default=10)
    sp.add_argument("-login", type=str, default=None)
    sp.add_argument("-no-headless", dest="headless", action="store_false")
    sp.add_argument("-output", type=str, default=None)
    sp.add_argument("-password", type=str, default=None)
    sp.add_argument("-silent", default=False, action="store_true")
    sp.add_argument("-timeout", type=int, default=30)
    sp.add_argument("-username", type=str, default=None)

    # ── scan ──────────────────────────────────────────────────────────────────
    sp = subparsers.add_parser("scan", help="Scan a target web host")
    sp.add_argument("target", type=str)
    sp.add_argument("--debug", action="store_true", default=False)
    sp.add_argument("-concurrency", type=int, default=3)
    sp.add_argument("-entry", type=str, default="/")
    sp.add_argument("-depth", type=int, default=3)
    sp.add_argument("-headless", dest="headless", default=True, action="store_true")
    sp.add_argument("-limit", type=int, default=10)
    sp.add_argument("-login", type=str, default=None)
    sp.add_argument("-no-headless", dest="headless", action="store_false")
    sp.add_argument("-output", type=str, default=None)
    sp.add_argument("-password", type=str, default=None)
    sp.add_argument("-silent", default=False, action="store_true")
    sp.add_argument(
        "-sub-depth", type=int, default=0, dest="sub_depth",
        help="Max crawl depth into discovered subdomains (default: 0 = detect only, do not scan)",
    )
    sp.add_argument("-timeout", type=int, default=30)
    sp.add_argument("-username", type=str, default=None)

    args = parser.parse_args()
    debug = getattr(args, "debug", False)
    _configure_logging(debug)

    logger.debug("startup  command=%r  target=%s  debug=%s", args.command, args.target, debug)

    if args.command == "auth":
        sys.exit(cmd_auth(args))
    elif args.command == "fingerprint":
        sys.exit(cmd_fingerprint(args))
    elif args.command == "scan":
        sys.exit(cmd_scan(args))


# ── Command implementations ───────────────────────────────────────────────────

def cmd_auth(args) -> int:
    _require_api_key("auth")
    client = get_client(debug=args.debug)
    _validate_license(client, "auth")

    logger.debug("auth_start  target=%r  entry=%r  username=%r", args.target, args.entry, args.username)

    auth_session = api.authenticate(
        target=args.target,
        entry=args.entry,
        username=args.username,
        password=args.password,
        headless=args.headless,
        silent=args.silent,
        cloud_client=client,
    )

    if not auth_session.success:
        print("[vertigo] Authentication failed", file=sys.stderr)
        return 1

    _write_output(auth_session, args.output, "Auth session", args.silent)
    logger.debug("auth_complete  success=True")
    return 0


def cmd_fingerprint(args) -> int:
    is_authenticated = bool(args.login and args.username)

    # Always pick up the API key from the environment — ML inference endpoints
    # require it even for unauthenticated scans.
    client = get_client(debug=args.debug)

    if is_authenticated:
        _require_api_key("authenticated fingerprint")
        _validate_license(client, "authenticated fingerprint")

    auth_session = None
    if is_authenticated:
        logger.debug("fingerprint_auth  login=%r  username=%r", args.login, args.username)
        auth_session = api.authenticate(
            target=args.target,
            entry=args.login,
            username=args.username,
            password=args.password,
            headless=args.headless,
            silent=args.silent,
            cloud_client=client,
        )
        if not auth_session.success:
            print("[vertigo] Authentication failed — aborting authenticated fingerprint", file=sys.stderr)
            return 1
    else:
        logger.debug("fingerprint_unauthenticated  target=%r  entry=%r", args.target, args.entry)

    crawl_result = api.fingerprint(
        target=args.target,
        entry=args.entry,
        depth=args.depth,
        limit=args.limit,
        timeout=args.timeout,
        concurrency=args.concurrency,
        silent=args.silent,
        session=auth_session,
        cloud_client=client,
    )

    _write_output(crawl_result, args.output, "Fingerprint", args.silent)
    status = crawl_result.get("metadata", {}).get("status", "UNKNOWN")
    logger.debug("fingerprint_complete  status=%r", status)
    return 0 if status in ("COMPLETE", "PARTIAL") else 1


def cmd_scan(args) -> int:
    is_authenticated = bool(args.login and args.username)

    # Always pick up the API key from the environment — ML inference endpoints
    # require it even for unauthenticated scans.
    client = get_client(debug=args.debug)

    if is_authenticated:
        _require_api_key("authenticated scan")
        _validate_license(client, "authenticated scan")

    auth_session = None
    if is_authenticated:
        logger.debug("scan_auth  login=%r  username=%r", args.login, args.username)
        auth_session = api.authenticate(
            target=args.target,
            entry=args.login,
            username=args.username,
            password=args.password,
            headless=args.headless,
            silent=args.silent,
            cloud_client=client,
        )
        if not auth_session.success:
            print("[vertigo] Authentication failed — aborting authenticated scan", file=sys.stderr)
            return 1
    else:
        logger.debug("scan_unauthenticated  target=%r  entry=%r", args.target, args.entry)

    crawl_result = api.scan(
        target=args.target,
        entry=args.entry,
        depth=args.depth,
        limit=args.limit,
        timeout=args.timeout,
        silent=args.silent,
        headless=args.headless,
        session=auth_session,
        cloud_client=client,
        sub_depth=args.sub_depth,
    )

    _write_output(crawl_result, args.output, "Scan", args.silent)
    status = crawl_result.get("metadata", {}).get("status", "UNKNOWN")
    logger.debug("scan_complete  status=%r", status)
    return 0 if status in ("COMPLETE", "PARTIAL") else 1


if __name__ == "__main__":
    __main__()
