"""Run the lab: python -m breachlab [--port 4160] [--fixed]"""

import argparse
import ipaddress
import sys

from .app import create_app, load_impl


def loopback_address(host: str) -> str:
    """Return `host` as a loopback IP literal, or raise ValueError. This app must never be reachable from a network."""
    address = "127.0.0.1" if host == "localhost" else host
    if not ipaddress.ip_address(address).is_loopback:  # also raises ValueError for anything that is not an IP
        raise ValueError(host)
    return address


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
    app = create_app(impl=load_impl("solutions" if args.fixed else "vulnerable"))
    print(f" * BreachLab ({'reference fixes' if args.fixed else 'vulnerable'}) on http://{args.host}:{args.port}/")
    app.run(host=host, port=args.port, threaded=True, use_reloader=not args.no_reload)


if __name__ == "__main__":
    main()
