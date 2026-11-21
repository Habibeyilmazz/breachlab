"""Run the lab: python -m breachlab [--port 4160] [--fixed]"""

import argparse
import sys
import threading
import traceback

from werkzeug.serving import is_running_from_reloader, make_server

from .app import DEFAULT_DATA_DIR, LOOPBACK_HOSTS, create_app, create_broken_app, load_impl
from .attacker import create_attacker_app


def loopback_address(host: str) -> str:
    """Return the address to bind for `host`, or raise ValueError. This app must never be reachable from a network.

    Only the names the app itself answers to are accepted (see loopback_only in app.py).
    """
    if host not in LOOPBACK_HOSTS:
        raise ValueError(host)
    return "127.0.0.1" if host == "localhost" else host


def origin(host, port):
    return f"http://{'[::1]' if host == '::1' else host}:{port}"


def start_attacker(host, port):
    """Serve Mallory's site in a background thread. Returns the port, or None if it is busy (the lab runs anyway)."""
    try:
        server = make_server(host, port, create_attacker_app(DEFAULT_DATA_DIR), threaded=True)
    except (OSError, OverflowError, SystemExit):  # werkzeug exits on a busy port, after saying so on stderr
        print(f" * Mallory's site could not start on port {port}; the CSRF challenge page explains a workaround.")
        return None
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return port


def port_number(text):
    port = int(text)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("must be between 1 and 65535")
    return port


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m breachlab", description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="loopback address to bind (anything else is refused)")
    parser.add_argument("--port", type=port_number, default=4160)
    parser.add_argument("--fixed", action="store_true", help="serve the reference fixes instead of the vulnerable code")
    parser.add_argument(
        "--attacker-port",
        type=port_number,
        help="port for Mallory's site, the CSRF challenge's attacker page (default: --port + 1)",
    )
    parser.add_argument("--no-reload", action="store_true", help="do not restart when a source file changes")
    args = parser.parse_args(argv)
    try:
        host = loopback_address(args.host)
    except ValueError:
        sys.exit(
            f"Refusing to bind to {args.host!r}: BreachLab is vulnerable on purpose and only runs on "
            "127.0.0.1 or ::1. Never expose it to a network."
        )
    attacker_port = args.attacker_port or args.port + 1
    if attacker_port == args.port:
        sys.exit("--attacker-port must differ from --port.")
    serving = args.no_reload or is_running_from_reloader()  # with the reloader, the parent process only watches files
    if serving:
        attacker_port = start_attacker(host, attacker_port)
    try:
        app = create_app(attacker_port=attacker_port, impl=load_impl("solutions" if args.fixed else "vulnerable"))
    except Exception:
        # A patch saved with a syntax error must not end the lab: keep serving (and watching files) until it is fixed.
        if not is_running_from_reloader():
            raise
        traceback.print_exc()
        app = create_broken_app(traceback.format_exc())
    if serving:
        mode = "reference fixes" if args.fixed else "vulnerable"
        print(f" * BreachLab ({mode}): open {origin(host, args.port)}/", flush=True)
    if serving and attacker_port:
        print(f" * Mallory's site (CSRF challenge): {origin(host, attacker_port)}/", flush=True)
    app.run(host=host, port=args.port, threaded=True, use_reloader=not args.no_reload)


if __name__ == "__main__":
    main()
