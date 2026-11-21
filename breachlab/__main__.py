"""Run the lab: python -m breachlab [--port 4160] [--fixed]"""

import argparse
import sys
import traceback

from werkzeug.serving import is_running_from_reloader

from .app import LOOPBACK_HOSTS, create_app, create_broken_app, load_impl


def loopback_address(host: str) -> str:
    """Return the address to bind for `host`, or raise ValueError. This app must never be reachable from a network.

    Only the names the app itself answers to are accepted (see loopback_only in app.py).
    """
    if host not in LOOPBACK_HOSTS:
        raise ValueError(host)
    return "127.0.0.1" if host == "localhost" else host


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m breachlab", description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="loopback address to bind (anything else is refused)")
    parser.add_argument("--port", type=int, default=4160)
    parser.add_argument("--fixed", action="store_true", help="serve the reference fixes instead of the vulnerable code")
    parser.add_argument("--no-reload", action="store_true", help="do not restart when a source file changes")
    args = parser.parse_args(argv)
    try:
        host = loopback_address(args.host)
    except ValueError:
        sys.exit(
            f"Refusing to bind to {args.host!r}: BreachLab is vulnerable on purpose and only runs on "
            "127.0.0.1 or ::1. Never expose it to a network."
        )
    try:
        app = create_app(impl=load_impl("solutions" if args.fixed else "vulnerable"))
    except Exception:
        # A patch saved with a syntax error must not end the lab: keep serving (and watching files) until it is fixed.
        if not is_running_from_reloader():
            raise
        traceback.print_exc()
        app = create_broken_app(traceback.format_exc())
    if args.no_reload or is_running_from_reloader():  # with the reloader, only the serving child announces itself
        mode = "reference fixes" if args.fixed else "vulnerable"
        print(f" * BreachLab ({mode}): open http://{'[::1]' if host == '::1' else host}:{args.port}/", flush=True)
    app.run(host=host, port=args.port, threaded=True, use_reloader=not args.no_reload)


if __name__ == "__main__":
    main()
