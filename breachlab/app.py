"""Quillbook, the fake notes-and-invoices app, plus the lab pages that wrap it.

The app's weak spots are not in this file: every hole lives in one small function
under breachlab/vulnerable/ (reached here through `impl()`), so it can be swapped
for the learner's patch or the reference fix. What IS in this file are the lab's
own safety rails, which are not part of any challenge:

  * is_local_request     refuses non-local clients and unknown Host headers
  * fetch_sandboxed      the SSRF "network" is the app itself, called in-process
  * download_export      traversal can leave exports/ but never the lab's data folder
"""

import hmac
import importlib
import ipaddress
import re
import secrets
import socket
import sqlite3
from functools import wraps
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from flask import (
    Flask,
    Response,
    abort,
    current_app,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash
from werkzeug.urls import iri_to_uri

from . import store
from .challenges import BY_ID, CHALLENGES, FLAGS

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_DATA_DIR = PACKAGE_DIR.parent / ".breachlab"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
HOST_HEADER = re.compile(r"(127\.0\.0\.1|localhost|\[::1\])(:\d{1,5})?")
USER_COLUMNS = {"username", "password_hash", "display_name", "email", "role", "credit_cents"}
PROFILE_FIELDS = {"display_name", "email"}
EMAIL = re.compile(r"[^@\s]+@[^@\s]+")
SANDBOX_NOTICE = (
    "Lab sandbox: BreachLab never opens outbound connections, so nothing was fetched. "
    "A real server would have requested this URL from inside its own network."
)
FAQ = [
    ("How do I export an invoice?", "Open the invoice and choose “Download text export”."),
    ("Who can read the team board?", "Everyone in your workspace sees every note."),
    (
        "How do I import an invoice from a supplier?",
        "Use Invoices, then “Import from URL”, and paste the supplier's link.",
    ),
    ("Where is my API token?", "On the Account page, under API access."),
    ("How do I change my email address?", "Edit it on the Account page and save."),
]


def load_impl(package="vulnerable", **overrides):
    """Load one implementation module per challenge from breachlab.<package>.

    overrides maps a challenge id to another package name, e.g. sqli="solutions".
    """
    return SimpleNamespace(
        **{c.id: importlib.import_module(f"breachlab.{overrides.get(c.id, package)}.{c.id}") for c in CHALLENGES}
    )


def is_loopback_host(host: str) -> bool:
    """True when `host` is a literal that means this machine. Never does a DNS lookup."""
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.inet_aton(host))  # 2130706433, 127.1, 0x7f.0.0.1
        except OSError:
            return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_unspecified


def _origin(parts, default_scheme):
    scheme = parts.scheme or default_scheme
    return scheme, parts.hostname, parts.port or {"http": 80, "https": 443}.get(scheme)


def is_external(target: str, own_origin: str) -> bool:
    """True when a browser following `Location: target` from `own_origin` would leave this app."""
    # Browsers drop whitespace and control characters and read "\" as "/".
    cleaned = re.sub(r"[\x00-\x20\x7f]", "", target).replace("\\", "/")
    try:
        parts, own = urlsplit(cleaned), urlsplit(own_origin)
        if parts.netloc:
            return _origin(parts, own.scheme) != _origin(own, own.scheme)
    except ValueError:  # not a URL a browser could follow
        return False
    return bool(parts.scheme)


def is_local_request() -> bool:
    """Safety rail: True when the request comes from this machine and is addressed to it.

    The Host check also stops DNS rebinding, where a hostile website points its own
    domain at 127.0.0.1 to read this deliberately vulnerable app from your browser.
    """
    try:
        remote_ok = ipaddress.ip_address(request.remote_addr or "").is_loopback
    except ValueError:
        remote_ok = False
    return remote_ok and HOST_HEADER.fullmatch(request.host) is not None


def create_broken_app(details: str):
    """Stand-in served while patched code fails to import, so the reloader lives on to see the next save."""
    app = Flask(__name__)

    @app.before_request
    def explain():
        if not is_local_request():
            abort(403)
        text = (
            "BreachLab could not load your code. Fix the error below and save the file:\n"
            f"the server restarts by itself.\n\n{details}"
        )
        return Response(text, 500, mimetype="text/plain")

    return app


def money(value):
    """Format cents as dollars; anything else (say, a UNION-injected string) is shown as is."""
    return f"${value / 100:,.2f}" if isinstance(value, int) else str(value)


def create_app(data_dir=None, impl=None):
    data_dir = Path(data_dir or DEFAULT_DATA_DIR).resolve()
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=store.init(data_dir),
        SESSION_COOKIE_SAMESITE="Lax",
        DATA_DIR=data_dir,
        IMPL=impl or load_impl(),
        INTERNAL_TOKEN=secrets.token_hex(16),
    )
    app.jinja_env.filters["money"] = money
    files_root = data_dir / "files"
    exports_dir = files_root / "exports"

    # ---- plumbing -------------------------------------------------------------------

    def impl_():
        return current_app.config["IMPL"]

    def db():
        if "db" not in g:
            g.db = store.connect(data_dir / "app.db")
        return g.db

    def lab():
        if "lab" not in g:
            g.lab = store.connect(data_dir / "lab.db")
        return g.lab

    def award(challenge_id):
        store.award(lab(), challenge_id)

    def own_origin():
        return request.host_url.rstrip("/")

    @app.teardown_appcontext
    def close_connections(_exc):
        for name in ("db", "lab"):
            conn = g.pop(name, None)
            if conn is not None:
                conn.close()

    @app.before_request
    def loopback_only():
        """Safety rail: serve this machine only, whatever address the server was bound to."""
        if not is_local_request():
            abort(403, "BreachLab only answers requests from and for this machine.")
        # A website the learner visits must not drive the holes (a link to the reflected XSS, a framed button).
        # The CSRF challenge's page on another port of this host is same-site; curl sends no such header.
        if request.headers.get("Sec-Fetch-Site") == "cross-site":
            abort(403, "BreachLab does not answer requests started by other websites. Type its address yourself.")
        # The lab's own buttons (reset, verify) must not be forgeable from other origins.
        if request.method == "POST" and request.path.startswith("/lab"):
            if request.headers.get("Origin", own_origin()) != own_origin():
                abort(403, "Lab actions must come from the lab's own pages.")

    @app.after_request
    def no_framing(response):
        # Clickjacking guard for browsers that do not send Sec-Fetch-Site.
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.before_request
    def load_user():
        g.user = None
        if "uid" in session:
            g.user = db().execute("SELECT * FROM users WHERE id = ?", (session["uid"],)).fetchone()

    def login_required(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login", next=request.full_path.rstrip("?")))
            return view(*args, **kwargs)

        return wrapper

    @app.context_processor
    def lab_context():
        def lab_status():
            done = store.progress(lab())
            # A page fetched by the SSRF sandbox is not the learner looking at the screen.
            fresh = [] if "X-Internal-Token" in request.headers else store.pop_fresh(lab())
            return {
                "challenges": CHALLENGES,
                "progress": done,
                "solved": sum(1 for row in done.values() if row["solved_at"]),
                "fresh": [BY_ID[i] for i in fresh if i in BY_ID],
                "reference_fixes": all(
                    getattr(m, "__name__", "").startswith("breachlab.solutions.") for m in vars(impl_()).values()
                ),
            }

        return {"lab_status": lab_status, "csrf_token": session.get("csrf", "")}

    @app.errorhandler(HTTPException)
    def http_error(error):
        if request.path.startswith(("/api/", "/internal/")):
            return jsonify(error=error.description), error.code
        # An unhandled exception is most likely the learner's patch: name it instead of "server overloaded".
        cause = getattr(error, "original_exception", None)
        return render_template("error.html", error=error, cause=cause), error.code

    # ---- Quillbook: sign in ---------------------------------------------------------

    @app.get("/")
    def home():
        return redirect(url_for("invoices") if g.user else url_for("lab_index"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            username = request.form.get("username", "")
            user = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
                session.clear()
                session["uid"] = user["id"]
                session["csrf"] = secrets.token_urlsafe(24)
                target = impl_().open_redirect.redirect_target(request.args.get("next", ""))
                try:
                    iri_to_uri(target)  # Werkzeug does this to Location later, outside Flask's error handling
                    response = redirect(target)  # refuses line breaks
                except ValueError:
                    abort(400, "You are signed in, but that next address cannot be used in a redirect.")
                if is_external(target, request.host_url):
                    award("open_redirect")
                return response
            error = "Wrong username or password."
        return render_template("login.html", error=error, learner=store.LEARNER), 401 if error else 200

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ---- Quillbook: invoices --------------------------------------------------------

    @app.get("/invoices")
    @login_required
    def invoices():
        query = request.args.get("q", "")[:200]
        error = None
        try:
            rows = impl_().sqli.search_invoices(db(), g.user["id"], query)
        except sqlite3.Error as exc:
            rows, error = [], f"Database error: {exc}"
        own = {r["id"] for r in db().execute("SELECT id FROM invoices WHERE owner_id = ?", (g.user["id"],))}
        if any(row[0] not in own for row in rows):
            award("sqli")
        return render_template("invoices.html", rows=rows, query=query, error=error)

    @app.get("/invoices/<int:invoice_id>")
    @login_required
    def invoice(invoice_id):
        row = impl_().idor.load_invoice(db(), g.user["id"], invoice_id)
        if row is None:
            abort(404, "No such invoice.")
        mine = row["owner_id"] == g.user["id"]
        if not mine:
            award("idor")
        owner = db().execute("SELECT display_name FROM users WHERE id = ?", (row["owner_id"],)).fetchone()
        return render_template("invoice.html", invoice=row, owner=owner, mine=mine)

    @app.get("/exports/download")
    @login_required
    def download_export():
        try:
            path = impl_().path_traversal.export_path(exports_dir, request.args.get("file", ""))
            real = None if path is None else Path(path).resolve()
        except (OSError, ValueError):
            abort(400, "Bad file name.")
        if real is None:
            abort(404, "No such export.")
        # Safety rail: the hole may leave exports/, but the lab never reads outside its own data folder.
        if not real.is_relative_to(files_root):
            award("path_traversal")
            return Response(
                f"Lab sandbox: this request escaped the exports folder and a real server would now read {real}.\n"
                "BreachLab only serves files from its own data folder. Try ../private/ instead.\n",
                403,
                mimetype="text/plain",
            )
        try:
            found = real.is_file()
        except OSError:  # e.g. a name longer than the file system allows
            found = False
        if not found:
            abort(404, "No such export.")
        if not real.is_relative_to(exports_dir):  # only a file that is really handed over counts
            award("path_traversal")
        return Response(real.read_text(errors="replace"), mimetype="text/plain")

    def fetch_sandboxed(url):
        """Safety rail: 'fetch' a URL without ever opening a socket.

        A URL that points back at this app is dispatched in-process, carrying the
        service token a real app server would use to talk to internal services.
        Everything else gets a notice instead of a request.
        """
        try:
            parts = urlsplit(url)
            host, port = parts.hostname or "", parts.port or 80
            own_port = urlsplit("//" + request.host).port or 80
        except ValueError:
            return "That is not a valid URL."
        if parts.scheme != "http" or not is_loopback_host(host) or port != own_port:
            return SANDBOX_NOTICE
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        headers = {"X-Internal-Token": current_app.config["INTERNAL_TOKEN"]}
        with current_app.app_context():  # a fresh `g`, so the inner request cannot disturb this one
            response = current_app.test_client().get(path, headers=headers)
        return f"HTTP {response.status_code}\n\n{response.get_data(as_text=True)[:4000]}"

    @app.route("/invoices/import", methods=["GET", "POST"])
    @login_required
    def import_invoice():
        url = request.form.get("url", "").strip()[:2000]
        preview = error = None
        if request.method == "POST":
            if impl_().ssrf.is_allowed_url(url):
                preview = fetch_sandboxed(url)
            else:
                error = "That address is not allowed."
        return render_template("import.html", url=url, preview=preview, error=error), 400 if error else 200

    @app.get("/internal/keys")
    def internal_keys():
        token = request.headers.get("X-Internal-Token", "")
        if not hmac.compare_digest(token, current_app.config["INTERNAL_TOKEN"]):
            abort(403, "Internal service. Only the Quillbook app server may call this.")
        award("ssrf")
        return jsonify(service="billing", api_key="qb-billing-live-7f3a9c", flag=FLAGS["ssrf"])

    # ---- Quillbook: notes and help --------------------------------------------------

    @app.route("/notes", methods=["GET", "POST"])
    @login_required
    def notes():
        if request.method == "POST":
            body = request.form.get("body", "").strip()[:2000]
            if body:
                with db():
                    db().execute("INSERT INTO notes (author_id, body) VALUES (?, ?)", (g.user["id"], body))
            return redirect(url_for("notes"))
        rows = (
            db()
            .execute(
                "SELECT notes.body, notes.created_at, users.display_name FROM notes"
                " JOIN users ON users.id = notes.author_id ORDER BY notes.id DESC"
            )
            .fetchall()
        )
        return render_template("notes.html", notes=rows, render_note=impl_().stored_xss.render_note)

    @app.get("/help")
    def help_centre():
        query = request.args.get("q", "")[:200]
        matches = [item for item in FAQ if query.lower() in " ".join(item).lower()]
        heading = impl_().reflected_xss.results_heading(query, len(matches)) if query else None
        return render_template("help.html", query=query, matches=matches, heading=heading)

    # ---- Quillbook: account, admin, API ---------------------------------------------

    @app.route("/account", methods=["GET", "POST"])
    @login_required
    def account():
        error = None
        if request.method == "POST":
            if not impl_().csrf.is_request_genuine(session.get("csrf", ""), request.form.get("csrf_token", "")):
                abort(403, "This form has expired. Reload the page and try again.")
            changes = impl_().mass_assignment.profile_changes(request.form.to_dict())
            # Column names cannot be bound as SQL parameters, so only real columns get through.
            changes = {k: str(v).strip()[:200] for k, v in changes.items() if k in USER_COLUMNS}
            try:
                if not changes.get("display_name", "x"):
                    raise ValueError("the display name cannot be empty.")
                if not EMAIL.fullmatch(changes.get("email", "a@b")):
                    raise ValueError("that does not look like an email address.")
                if changes:
                    assignments = ", ".join(f"{column} = ?" for column in changes)
                    with db():
                        db().execute(f"UPDATE users SET {assignments} WHERE id = ?", (*changes.values(), g.user["id"]))
            except (sqlite3.Error, ValueError) as exc:
                error = f"Could not save: {exc}"
            else:
                if set(changes) - PROFILE_FIELDS:
                    award("mass_assignment")
                if changes and request.headers.get("Origin", own_origin()) != own_origin():
                    award("csrf")
                return redirect(url_for("account", saved=1))
        token = impl_().weak_jwt.issue({"sub": g.user["username"], "role": g.user["role"]})
        return render_template("account.html", token=token, error=error, saved="saved" in request.args)

    @app.get("/admin")
    @login_required
    def admin():
        if g.user["role"] != "admin":
            abort(403, "Administrators only.")
        users = db().execute("SELECT username, display_name, email, role, credit_cents FROM users").fetchall()
        return render_template("admin.html", users=users, flag=FLAGS["mass_assignment"])

    def bearer():
        """Return (token, claims) for the request's Bearer token, or answer 401."""
        scheme, _, token = request.headers.get("Authorization", "").partition(" ")
        token = token.strip()
        claims = impl_().weak_jwt.verify(token) if scheme.lower() == "bearer" else None
        if not isinstance(claims, dict):
            abort(401, "A valid Bearer token is required.")
        return token, claims

    @app.get("/api/me")
    def api_me():
        return jsonify(bearer()[1])

    @app.get("/api/admin/report")
    def api_admin_report():
        token, claims = bearer()
        if claims.get("role") != "admin":
            abort(403, "This token does not have the admin role.")
        total = db().execute("SELECT SUM(amount_cents) FROM invoices").fetchone()[0]
        report = {"report": "all-workspaces revenue", "total_cents": total}
        # Alice can make herself a real admin (mass assignment). The token Quillbook then issues her is no forgery.
        holder = db().execute("SELECT * FROM users WHERE username = ?", (str(claims.get("sub", "")),)).fetchone()
        if holder and token == impl_().weak_jwt.issue({"sub": holder["username"], "role": holder["role"]}):
            note = (
                "This is the token Quillbook issued to a real admin account, so nothing was forged. "
                "Reset the app data on the lab page to be an ordinary user again, or forge a token of your own."
            )
            return jsonify(**report, note=note)
        award("weak_jwt")
        return jsonify(**report, flag=FLAGS["weak_jwt"])

    # ---- lab pages ------------------------------------------------------------------

    @app.get("/lab")
    def lab_index():
        return render_template("lab/index.html")

    def challenge_page(challenge_id, report=None):
        challenge = BY_ID.get(challenge_id) or abort(404, "No such challenge.")
        position = CHALLENGES.index(challenge)
        return render_template(
            "lab/challenge.html",
            challenge=challenge,
            hints=[Markup(hint.replace("ORIGIN", own_origin())) for hint in challenge.hints],  # Host is validated
            number=position + 1,
            following=CHALLENGES[position + 1] if position + 1 < len(CHALLENGES) else None,
            state=store.progress(lab()).get(challenge_id),
            solution=(PACKAGE_DIR / "solutions" / f"{challenge_id}.py").read_text(),
            report=report,
        )

    @app.get("/lab/c/<challenge_id>")
    def lab_challenge(challenge_id):
        return challenge_page(challenge_id)

    @app.post("/lab/c/<challenge_id>/verify")
    def lab_verify(challenge_id):
        from . import checks

        if challenge_id not in BY_ID:
            abort(404, "No such challenge.")
        report = checks.run(challenge_id, impl_())
        store.set_fixed(lab(), challenge_id, report.ok)
        return challenge_page(challenge_id, report)

    @app.post("/lab/reset")
    def lab_reset():
        store.seed_app(data_dir)
        if request.form.get("what") == "everything":
            store.reset_progress(lab())
        return redirect(url_for("lab_index", reset=1))

    @app.post("/lab/xss")
    def lab_xss():
        """Called by the alert() hook in lab.js: script ran on a page, so the XSS worked."""
        report = request.get_json(silent=True)
        path = report.get("path") if isinstance(report, dict) else None
        challenge_id = {"/notes": "stored_xss", "/help": "reflected_xss"}.get(path if isinstance(path, str) else "")
        if challenge_id is None:
            return jsonify(captured=None)
        if not store.award(lab(), challenge_id):
            return jsonify(captured=None)
        store.pop_fresh(lab())  # lab.js shows the banner itself
        challenge = BY_ID[challenge_id]
        return jsonify(
            captured=challenge.title, flag=challenge.flag, url=url_for("lab_challenge", challenge_id=challenge_id)
        )

    return app
