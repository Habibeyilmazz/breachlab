"""Attack-and-regression checks, one per challenge.

Each check drives a fresh copy of the app like a browser would and answers two questions:
does the attack still work, and does the legitimate feature still work? A fix is accepted
only when the answers are "no" and "yes". Used by fix_tests/, by tests/ and by the
"Check my fix" button.
"""

import base64
import hashlib
import hmac
import json
import re
import tempfile
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path

from flask import got_request_exception

from . import store
from .store import LEARNER

WORDLIST = Path(__file__).resolve().parent / "wordlists" / "jwt-secrets.txt"


@dataclass
class Report:
    attack: str | None  # how the attack succeeded, or None when it was blocked
    broken: str | None  # which legitimate behaviour stopped working, or None

    @property
    def ok(self):
        return self.attack is None and self.broken is None


def run(challenge_id, impl) -> Report:
    """Check one challenge against the implementation modules in `impl`, on throwaway data."""
    from .app import create_app

    crashes = []  # exceptions the patched code raised while serving a request (each one became a 500 page)
    with tempfile.TemporaryDirectory(prefix="breachlab-check-") as tmp:
        app = create_app(tmp, impl)
        try:
            with got_request_exception.connected_to(lambda _sender, exception, **_: crashes.append(exception), app):
                client = app.test_client()
                _login(client)
                report = Report(*CHECKS[challenge_id](client))
        except Exception as exc:  # a crash in patched code is a failed check, not a crashed lab
            return Report(None, f"the check crashed: {exc!r}")
    if crashes and report.broken:
        report.broken += f" (your code raised {crashes[0]!r}; the traceback is in the terminal)"
    return report


def _login(client, next_url=None):
    username, password = LEARNER
    query = {"next": next_url} if next_url is not None else None
    return client.post("/login", query_string=query, data={"username": username, "password": password})


def _text(response):
    return response.get_data(as_text=True)


def _csrf_token(client):
    return re.search(r'name="csrf_token" value="([^"]*)"', _text(client.get("/account"))).group(1)


def _save_account(client, **fields):
    return client.post("/account", data={"csrf_token": _csrf_token(client), **fields})


class _ScriptFinder(HTMLParser):
    """Finds markup that can run script. Quillbook's own pages have none besides lab.js."""

    def __init__(self):
        super().__init__()
        self.found = None

    def handle_starttag(self, tag, attrs):
        attrs = {name: value or "" for name, value in attrs}
        if tag == "script" and "lab.js" not in attrs.get("src", ""):
            self.found = self.found or "a <script> element"
        for name, value in attrs.items():
            if name.startswith("on"):
                self.found = self.found or f"an {name}= handler on <{tag}>"
            if name in ("href", "src", "action", "formaction") and value.strip().lower().startswith("javascript:"):
                self.found = self.found or f"a javascript: URL on <{tag}>"


def _live_markup(page):
    """Describe the first script-capable construct in an HTML page, or return None."""
    finder = _ScriptFinder()
    finder.feed(page)
    return finder.found


XSS_PAYLOADS = (
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    '<a href="javascript:alert(1)">details</a>',
)


def check_sqli(c):
    attack = None
    payloads = (
        "' OR 1=1--",
        "' UNION SELECT id, username, 0, password_hash FROM users--",
        "'' OR 1=1--",  # beats escaping only the first quote
        "\\' OR 1=1--",  # beats backslash-escaping, which SQLite does not understand
    )
    for payload in payloads:
        page = _text(c.get("/invoices", query_string={"q": payload}))
        if "Harbor Freight" in page or "scrypt:" in page:
            attack = f"searching for {payload} returned data that is not alice's"
            break
    page = _text(c.get("/invoices", query_string={"q": "O'Brien"}))
    broken = None
    if "O&#39;Brien &amp; Sons" not in page:
        broken = "searching for O'Brien should find the O'Brien & Sons invoice"
    elif "Acme Robotics" in page:
        broken = "searching for O'Brien should not list other customers"
    return attack, broken


def check_reflected_xss(c):
    attack = None
    for payload in XSS_PAYLOADS:
        found = _live_markup(_text(c.get("/help", query_string={"q": payload})))
        if found:
            attack = f"/help?q={payload} put {found} into the page"
            break
    page = _text(c.get("/help", query_string={"q": "a<b export"}))
    broken = None if "a&lt;b export" in page else "the heading should show the search term as text (a<b export)"
    return attack, broken


def check_stored_xss(c):
    attack = None
    for payload in XSS_PAYLOADS:
        c.post("/notes", data={"body": payload})
        found = _live_markup(_text(c.get("/notes")))
        if found:
            attack = f"the note {payload} put {found} into the board"
            break
    c.post("/notes", data={"body": "Totals: 5 < 6 & 7 > 2\nsecond line"})
    page = _text(c.get("/notes"))
    broken = None
    # Either <br> or a kept newline (styled with white-space: pre-line) is a fine way to show line breaks.
    if not re.search(r"Totals: 5 &lt; 6 &amp; 7 &gt; 2\s*(<br\s*/?>)?\s*second line", page):
        broken = "a two-line note with < and & in it should be shown as the author typed it"
    return attack, broken


def check_idor(c):
    theirs = c.get("/invoices/2001")
    attack = "alice can open Bob's invoice 2001" if theirs.status_code == 200 and "Harbor" in _text(theirs) else None
    mine = c.get("/invoices/1001")
    broken = None if mine.status_code == 200 and "Acme Robotics" in _text(mine) else "alice should see her invoice 1001"
    return attack, broken


def check_path_traversal(c):
    private = Path(c.application.config["DATA_DIR"]) / "files" / "private" / "payroll-2026.txt"
    attack = None
    for name in (
        "../private/payroll-2026.txt",
        "x/../../private/payroll-2026.txt",
        str(private),
        "../../../../etc/hosts",
    ):
        body = _text(c.get("/exports/download", query_string={"file": name}))
        if "Payroll 2026" in body or "Lab sandbox" in body:
            attack = f"file={name} escaped the exports folder"
            break
    mine = c.get("/exports/download", query_string={"file": "invoice-1001.txt"})
    broken = None if mine.status_code == 200 and "Acme Robotics" in _text(mine) else "invoice-1001.txt should download"
    return attack, broken


def check_open_redirect(c):
    attack = None
    for target in (
        "https://evil.example/",
        "//evil.example/",
        "/\\evil.example/",
        "\\\\evil.example/",
        "/\t/evil.example/",
    ):
        location = _login(c.application.test_client(), target).headers.get("Location", "")
        if _is_external(location):
            attack = f"/login?next={target!r} redirects to {location!r}"
            break
    location = _login(c.application.test_client(), "/notes?from=login").headers.get("Location")
    broken = None if location == "/notes?from=login" else "next=/notes?from=login should return the user to that page"
    return attack, broken


def _is_external(location):
    from .app import is_external

    return is_external(location, "http://localhost")


def _alice_record(c):
    conn = store.connect(Path(c.application.config["DATA_DIR"]) / "app.db")
    try:
        return dict(conn.execute("SELECT * FROM users WHERE id = 1").fetchone())
    finally:
        conn.close()


def check_mass_assignment(c):
    attack = None
    before = _alice_record(c)
    extras = {"role": "admin", "credit_cents": "99999900", "username": "mallory", "password_hash": "x", "id": "3"}
    for field, value in extras.items():
        _save_account(c, display_name="Alice Moreau", email="alice@quillbook.test", **{field: value})
        if _alice_record(c)[field] != before[field]:
            attack = f"posting {field}={value} with the profile form changed alice's {field}"
            break
    _save_account(c, display_name="Alice M.", email="alice.m@quillbook.test")
    page = _text(c.get("/account"))
    broken = None if "Alice M." in page and "alice.m@quillbook.test" in page else "name and email should still save"
    return attack, broken


def check_csrf(c):
    attack = None
    forged = {"display_name": "Alice Moreau", "email": "attacker@evil.test"}
    real = _csrf_token(c)
    guesses = {
        "no token": {},
        "an empty token": {"csrf_token": ""},
        "a guessed token": {"csrf_token": "guess"},
        "only the first character of the token": {"csrf_token": real[:1]},
        "the token minus its last character": {"csrf_token": real[:-1]},
        "the token with extra characters": {"csrf_token": real + "x"},
    }
    for description, extra in guesses.items():
        c.post("/account", data={**forged, **extra}, headers={"Origin": "http://127.0.0.1:8001"})
        if "attacker@evil.test" in _text(c.get("/account")):
            attack = f"a cross-origin post with {description} changed alice's email"
            break
    _save_account(c, display_name="Alice Moreau", email="alice.new@quillbook.test")
    broken = None if "alice.new@quillbook.test" in _text(c.get("/account")) else "the real form should still save"
    return attack, broken


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _forge(secret: bytes | None, alg: str, claims: dict) -> str:
    signing_input = f"{_b64(json.dumps({'alg': alg, 'typ': 'JWT'}).encode())}.{_b64(json.dumps(claims).encode())}"
    if secret is None:
        return signing_input + "."
    return f"{signing_input}.{_b64(hmac.new(secret, signing_input.encode(), hashlib.sha256).digest())}"


def check_weak_jwt(c):
    def admin_report(token):
        return c.get("/api/admin/report", headers={"Authorization": f"Bearer {token}"}).status_code == 200

    admin = {"sub": "alice", "role": "admin"}
    token = re.search(r"eyJ[\w-]+\.[\w-]+\.[\w-]*", _text(c.get("/account"))).group(0)
    signing_input, _, signature = token.rpartition(".")
    attack = None
    for alg in ("none", "None", "NONE"):
        if admin_report(_forge(None, alg, admin)):
            attack = f'an unsigned token with "alg": "{alg}" was accepted as admin'
            break
    if attack is None:
        for word in WORDLIST.read_text(encoding="utf-8").split():
            if _b64(hmac.new(word.encode(), signing_input.encode(), hashlib.sha256).digest()) == signature:
                if admin_report(_forge(word.encode(), "HS256", admin)):
                    attack = f"the signing secret is the dictionary word {word!r}, so an admin token can be forged"
                break
    me = c.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    header, payload, signature = token.split(".")
    tampered = f"{header}.{_b64(json.dumps(admin).encode())}.{signature}"
    broken = None
    if me.status_code != 200 or me.get_json().get("sub") != "alice":
        broken = "the token shown on the account page should still work for /api/me"
    elif c.get("/api/me", headers={"Authorization": f"Bearer {tampered}"}).status_code == 200:
        attack = attack or "a token with edited claims and the old signature was accepted"
    return attack, broken


def check_ssrf(c):
    attack = None
    for host in (
        "127.0.0.1",
        "localhost",
        "[::1]",
        "2130706433",
        "127.1",
        "0x7f.0.0.1",
        "0.0.0.0",
        "[::ffff:127.0.0.1]",
    ):
        url = f"http://{host}/internal/keys"
        if "qb-billing-live" in _text(c.post("/invoices/import", data={"url": url})):
            attack = f"importing {url} returned the internal billing keys"
            break
    # Internal addresses the sandbox will not really fetch: here the decision itself is the evidence.
    for host in ("169.254.169.254", "10.0.0.5", "192.168.1.1", "172.16.0.9", "[fd00::1]", "[fe80::1]"):
        url = f"http://{host}/latest/meta-data/"
        if attack is None and "Lab sandbox" in _text(c.post("/invoices/import", data={"url": url})):
            attack = f"{url} was accepted for fetching, and it is an internal address"
    public = c.post("/invoices/import", data={"url": "http://1.1.1.1/invoice.json"})
    broken = (
        None if public.status_code == 200 and "Lab sandbox" in _text(public) else "public URLs should still be accepted"
    )
    return attack, broken


CHECKS = {
    "sqli": check_sqli,
    "reflected_xss": check_reflected_xss,
    "stored_xss": check_stored_xss,
    "idor": check_idor,
    "path_traversal": check_path_traversal,
    "open_redirect": check_open_redirect,
    "mass_assignment": check_mass_assignment,
    "csrf": check_csrf,
    "weak_jwt": check_weak_jwt,
    "ssrf": check_ssrf,
}
