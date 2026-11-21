"""Mallory's site: a second origin on this machine for the CSRF challenge.

It serves one page, the HTML the learner writes on the challenge page (saved to
<data dir>/attacker.html), at / on the port after the lab's. Another port is another
origin but the same site, which is exactly what the challenge needs. The same
loopback rails as the lab apply.
"""

from pathlib import Path

from flask import Flask, Response, abort, request

from .app import is_local_request

PAGE_FILE = "attacker.html"
MAX_PAGE = 20_000
STARTER_PAGE = """<!doctype html>
<title>Totally harmless page</title>
<h1>Win a free coffee!</h1>
<!-- You are Mallory. Write the attack here: this page is served from another origin. -->
"""


def page_path(data_dir) -> Path:
    return Path(data_dir) / PAGE_FILE


def read_page(data_dir) -> str:
    try:
        return page_path(data_dir).read_text(encoding="utf-8")
    except FileNotFoundError:
        return STARTER_PAGE


def create_attacker_app(data_dir):
    app = Flask(__name__)

    @app.before_request
    def loopback_only():
        if not is_local_request():
            abort(403)
        if request.headers.get("Sec-Fetch-Site") == "cross-site":
            abort(403)

    @app.get("/")
    def page():
        return Response(read_page(data_dir), mimetype="text/html")

    @app.errorhandler(404)
    def elsewhere(_error):
        return Response("Mallory's site. The page you wrote is at /.\n", 404, mimetype="text/plain")

    return app
