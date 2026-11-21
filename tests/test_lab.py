"""The lab around the app: progress, hints, fix checking, reset, and the safety rails."""

import http.client
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from types import SimpleNamespace

import pytest

from breachlab import checks, store
from breachlab.__main__ import loopback_address, main
from breachlab.app import PACKAGE_DIR, SANDBOX_NOTICE, create_app, create_broken_app, is_external, is_loopback_host
from breachlab.challenges import CHALLENGES


def text(response):
    return response.get_data(as_text=True)


# ---- lab pages -----------------------------------------------------------------------


def test_progress_page_lists_every_challenge(make_client):
    page = text(make_client(login=False).get("/lab"))
    assert all(c.title in page for c in CHALLENGES)
    assert "0 of 11 flags" in page and "never be deployed" in page


@pytest.mark.parametrize("challenge", CHALLENGES, ids=lambda c: c.id)
def test_challenge_page_shows_story_hints_and_fix_instructions(challenge, make_client):
    page = text(make_client(login=False).get(f"/lab/c/{challenge.id}"))
    assert page.count("<details>") == 3
    assert "&lt;code&gt;" not in page and "ORIGIN" not in page  # hints are trusted HTML, rendered as such
    assert f"breachlab/vulnerable/{challenge.id}.py" in page
    assert f"pytest fix_tests -k {challenge.id}" in page
    assert "Why this fix works" in page


def test_progress_page_says_when_the_reference_fixes_are_running(make_client):
    assert "running the reference fixes" in text(make_client("solutions", login=False).get("/lab"))
    assert "running the reference fixes" not in text(make_client("vulnerable", sqli="solutions").get("/lab"))


def test_hints_use_the_address_the_learner_is_browsing(make_client):
    page = text(make_client(login=False).get("/lab/c/ssrf", headers={"Host": "localhost:4160"}))
    assert "Import <code>http://localhost:4160/internal/keys</code>" in page


def test_unknown_challenge_is_a_404(make_client):
    client = make_client(login=False)
    assert client.get("/lab/c/nope").status_code == 404
    assert client.post("/lab/c/nope/verify").status_code == 404


def test_capturing_a_flag_shows_a_banner_once_and_updates_progress(make_client):
    client = make_client()
    first = text(client.get("/invoices/2001"))
    assert "Flag captured" in first and "1 of 11 flags" in first
    assert "Flag captured: " not in text(client.get("/invoices"))
    assert text(client.get("/lab")).count("stamp-captured") == 1


def test_xss_beacon_captures_only_for_the_pages_with_an_xss_challenge(make_client, captured):
    client = make_client()
    assert client.post("/lab/xss", json={"path": "/account"}).get_json() == {"captured": None}
    assert captured() == set()
    first = client.post("/lab/xss", json={"path": "/notes"}).get_json()
    assert (first["captured"], first["url"]) == ("Stored XSS", "/lab/c/stored_xss") and first["flag"].startswith("BL{")
    assert client.post("/lab/xss", json={"path": "/notes"}).get_json() == {"captured": None}
    assert client.post("/lab/xss", json={"path": "/help"}).get_json()["captured"] == "Reflected XSS"
    assert captured() == {"stored_xss", "reflected_xss"}


def test_check_my_fix_reports_failure_on_vulnerable_code(make_client):
    page = text(make_client().post("/lab/c/idor/verify"))
    assert "Not fixed yet." in page and "alice can open Bob" in page
    assert "stamp-fixed" not in page


def test_check_my_fix_records_success_on_fixed_code(make_client):
    client = make_client("vulnerable", idor="solutions")
    assert "The attack is blocked and the feature still works" in text(client.post("/lab/c/idor/verify"))
    assert text(client.get("/lab")).count("stamp-fixed") == 1


def test_reset_restores_data_and_keeps_progress_unless_asked(make_client, captured):
    client = make_client()
    client.post("/notes", data={"body": "temporary note"})
    client.get("/invoices/2001")
    client.post("/lab/reset", data={"what": "data"})
    assert "temporary note" not in text(client.get("/notes"))
    assert captured() == {"idor"}
    client.post("/lab/reset", data={"what": "everything"})
    assert captured() == set()


def test_data_survives_a_restart(tmp_path):
    from breachlab.app import create_app

    secret = create_app(tmp_path).config["SECRET_KEY"]
    lab = store.connect(tmp_path / "lab.db")
    store.award(lab, "idor")
    lab.close()
    again = create_app(tmp_path)
    assert again.config["SECRET_KEY"] == secret
    assert "1 of 11 flags" in text(again.test_client().get("/lab"))


# ---- a learner's broken patch must not take the lab down ----------------------------------


def test_an_exception_in_patched_code_is_named_on_the_page_and_in_the_fix_check(make_client):
    client = make_client()
    # A namespace of its own: load_impl() hands out the real modules, which other tests share.
    client.application.config["IMPL"].idor = SimpleNamespace(load_invoice=lambda *args: undefined_name)  # noqa: F821
    page = text(client.get("/invoices/1001"))
    assert "NameError: name &#39;undefined_name&#39; is not defined" in page and "overloaded" not in page
    report = text(client.post("/lab/c/idor/verify"))
    assert "Not fixed yet." in report and "your code raised NameError" in report


def test_the_stand_in_for_code_that_does_not_import_keeps_the_host_check():
    client = create_broken_app("SyntaxError: '(' was never closed").test_client()
    response = client.get("/lab")
    assert response.status_code == 500 and "SyntaxError" in text(response) and "save the file" in text(response)
    assert client.get("/lab", headers={"Host": "evil.example"}).status_code == 403
    assert "SyntaxError" not in text(client.get("/lab", environ_base={"REMOTE_ADDR": "192.168.1.50"}))


def test_saving_a_syntax_error_does_not_kill_the_server(tmp_path):
    """The real thing: a server with the reloader, a patch that does not compile, then the corrected patch."""
    port = 4169
    shutil.copytree(PACKAGE_DIR, tmp_path / "breachlab", ignore=shutil.ignore_patterns("__pycache__"))
    patched = tmp_path / "breachlab" / "vulnerable" / "idor.py"
    good = patched.read_text()

    def wait_for(status, needle):
        for _attempt in range(100):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/lab", timeout=5) as response:
                    seen = response.status, response.read().decode()
            except urllib.error.HTTPError as error:
                seen = error.code, error.read().decode()
            except (OSError, http.client.HTTPException) as error:  # not listening yet, or cut off by a restart
                seen = None, str(error)
            if seen[0] == status and needle in seen[1]:
                return
            assert server.poll() is None, "the server exited"
            time.sleep(0.2)
        raise AssertionError(f"still waiting for {status} with {needle!r}; last saw {seen}")

    server = subprocess.Popen(
        [sys.executable, "-m", "breachlab", "--port", str(port), "--attacker-port", "4165"], cwd=tmp_path
    )
    try:
        wait_for(200, "Break it, then fix it.")
        patched.write_text(good + "\ndef oops(:\n")
        wait_for(500, "SyntaxError")
        patched.write_text(good)
        wait_for(200, "Break it, then fix it.")
        # The restarted server serves Mallory's site again on the same port.
        with urllib.request.urlopen("http://127.0.0.1:4165/", timeout=5) as response:
            assert b"Win a free coffee!" in response.read()
    finally:
        server.terminate()  # the reloader parent takes its serving child down with it
        server.wait(timeout=10)


# ---- the app behaves like an app ------------------------------------------------------


def test_pages_require_login_and_return_after_it(make_client):
    client = make_client(login=False)
    response = client.get("/notes")
    assert response.status_code == 302 and response.headers["Location"] == "/login?next=/notes"
    assert client.post("/login", data={"username": "alice", "password": "wrong"}).status_code == 401


def test_admin_page_is_for_admins(make_client):
    assert make_client().get("/admin").status_code == 403


def test_account_rejects_empty_name_and_bad_email(make_client):
    client = make_client()
    assert "cannot be empty" in text(client.post("/account", data={"display_name": " ", "email": "a@b.test"}))
    assert "email address" in text(client.post("/account", data={"display_name": "A", "email": "nope"}))


def test_import_preview_keeps_the_user_signed_in(make_client):
    client = make_client()
    page = text(client.post("/invoices/import", data={"url": "http://localhost/login"}))
    assert "HTTP 200" in page and "Sign out" in page
    assert "Sign out" in text(client.get("/invoices"))


@pytest.mark.parametrize("target", ["http://[", "http://a:99999999/", "http://127.0.0.1:x/", "/x\r\nSet-Cookie: a=b"])
def test_a_next_address_that_cannot_be_a_redirect_is_a_400_not_a_crash(target, make_client):
    client = make_client(login=False)
    response = client.post(
        "/login", query_string={"next": target}, data={"username": "alice", "password": "alice-demo"}
    )
    assert response.status_code == 400 and "Set-Cookie: a=b" not in str(response.headers)
    assert "Sign out" in text(client.get("/invoices"))  # the sign-in itself went through


def test_an_overlong_export_name_is_a_404(make_client):
    assert make_client().get("/exports/download", query_string={"file": "x" * 5000}).status_code == 404


@pytest.mark.parametrize("package", ["vulnerable", "solutions"])
def test_an_invoice_number_beyond_sqlite_integers_is_a_404(make_client, package):
    assert make_client(package).get("/invoices/99999999999999999999").status_code == 404


@pytest.mark.parametrize("body", [[1], "x", 7, None, {"path": {"a": 1}}, {"path": ["/notes"]}])
def test_xss_beacon_ignores_malformed_reports(body, make_client, captured):
    assert make_client().post("/lab/xss", json=body).get_json() == {"captured": None}
    assert captured() == set()


def test_internal_keys_are_refused_to_browsers(make_client, captured):
    response = make_client().get("/internal/keys")
    assert response.status_code == 403 and "qb-billing" not in text(response)
    assert captured() == set()


# ---- safety rails ---------------------------------------------------------------------


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "::", "example.com", "", "127.0.0.2"])
def test_refuses_to_bind_anything_but_loopback(host, capsys):
    with pytest.raises(ValueError):
        loopback_address(host)
    with pytest.raises(SystemExit) as exit_info:
        main(["--host", host])
    assert "Refusing to bind" in str(exit_info.value)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_accepts_the_loopback_addresses_the_app_answers_to(host, make_client):
    address = loopback_address(host)
    assert address in ("127.0.0.1", "::1")
    bracketed = f"[{address}]" if ":" in address else address
    assert make_client(login=False).get("/lab", headers={"Host": f"{bracketed}:4160"}).status_code == 200


def test_non_local_clients_are_refused(make_client):
    client = make_client(login=False)
    assert client.get("/lab", environ_base={"REMOTE_ADDR": "192.168.1.50"}).status_code == 403
    assert client.get("/lab", environ_base={"REMOTE_ADDR": "127.0.0.1"}).status_code == 200


@pytest.mark.parametrize(
    "host",
    [
        "evil.example", "evil.example:4160", "127.0.0.1.evil.example", "192.168.1.10:4160", "127.0.0.2:4160",
        "localhost@evil.example", "localhost:4160@evil.example", "localhost:port", "localhost:123456",
        'localhost:4160"><script>alert(1)</script>', "localhost:4160/evil", "",
    ],
)  # fmt: skip
def test_unknown_host_headers_are_refused(host, make_client):
    assert make_client(login=False).get("/lab", headers={"Host": host}).status_code == 403


@pytest.mark.parametrize("host", ["127.0.0.1:4160", "localhost:4160", "[::1]:4160"])
def test_loopback_host_headers_are_served(host, make_client):
    assert make_client(login=False).get("/lab", headers={"Host": host}).status_code == 200


def test_lab_actions_cannot_be_forged_from_another_origin(make_client, captured):
    client = make_client()
    client.get("/invoices/2001")
    evil = {"Origin": "http://127.0.0.1:8001"}
    assert client.post("/lab/reset", data={"what": "everything"}, headers=evil).status_code == 403
    assert client.post("/lab/xss", json={"path": "/notes"}, headers=evil).status_code == 403
    assert captured() == {"idor"}
    assert client.post("/lab/reset", data={"what": "data"}, headers={"Origin": "http://localhost"}).status_code == 302


def test_other_websites_cannot_drive_the_lab(make_client, captured):
    # A page on the internet the learner happens to visit links to the reflected XSS or frames the reset button.
    client = make_client()
    cross = {"Sec-Fetch-Site": "cross-site"}
    assert client.get("/help?q=<script>alert(1)</script>", headers=cross).status_code == 403
    assert client.get("/lab", headers={**cross, "Sec-Fetch-Dest": "iframe"}).status_code == 403
    assert client.get("/invoices/2001", headers=cross).status_code == 403
    assert captured() == set()
    # The CSRF challenge's attacker page on another port of the same host is same-site, and typed addresses are "none".
    for site in ("same-site", "same-origin", "none"):
        assert client.get("/invoices/2001", headers={"Sec-Fetch-Site": site}).status_code == 200


def test_pages_cannot_be_framed(make_client):
    assert make_client(login=False).get("/lab").headers["X-Frame-Options"] == "DENY"


def test_traversal_never_reads_outside_the_lab_data_folder(make_client, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "secret.txt"
    outside.write_text("really private")
    response = make_client().get("/exports/download", query_string={"file": str(outside)})
    assert response.status_code == 403
    assert "Lab sandbox" in text(response) and "really private" not in text(response)


def test_traversal_with_a_nul_byte_is_a_clean_error(make_client):
    assert make_client().get("/exports/download", query_string={"file": "a\x00b"}).status_code in (400, 404)


@pytest.mark.parametrize(
    "url", ["http://1.1.1.1/", "http://example.com/", "https://127.0.0.1/", "http://127.0.0.1:9/", "file:///etc/hosts"]
)
def test_import_never_opens_a_socket(url, make_client, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("the lab tried to use the network")

    client = make_client()
    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    page = text(client.post("/invoices/import", data={"url": url}))
    assert SANDBOX_NOTICE.split(":")[0] in page or "not allowed" in page


@pytest.mark.parametrize(
    "host, expected",
    [
        ("127.0.0.1", True), ("localhost", True), ("::1", True), ("2130706433", True), ("127.1", True),
        ("0x7f.0.0.1", True), ("0.0.0.0", True), ("::ffff:127.0.0.1", True),
        ("1.1.1.1", False), ("192.168.1.1", False), ("example.com", False), ("localhost.evil.example", False), ("", False),
    ],
)  # fmt: skip
def test_is_loopback_host(host, expected):
    assert is_loopback_host(host) is expected


@pytest.mark.parametrize(
    "target, expected",
    [
        ("https://evil.example/", True), ("//evil.example", True), ("/\\evil.example", True),
        ("\\\\evil.example", True), ("https:evil.example", True), (" //evil.example", True),
        ("javascript:alert(1)", True), ("http://localhost:4160/invoices", False), ("//localhost:4160/x", False),
        ("https://localhost:4160/", True), ("http://localhost/", True), ("http://localhost:4161/", True),
        ("http://localhost:99999/", False), ("/invoices?q=a", False), ("/", False), ("invoices", False), ("", False),
    ],
)  # fmt: skip
def test_is_external(target, expected):
    assert is_external(target, "http://localhost:4160/") is expected


def test_is_external_knows_default_ports():
    assert is_external("http://localhost:80/x", "http://localhost") is False
    assert is_external("https://localhost/x", "http://localhost") is True


def test_resetting_while_the_lab_is_in_use_never_breaks_a_request(tmp_path):
    import threading

    store.init(tmp_path)
    errors, stop = [], threading.Event()

    def reset():
        try:
            for _ in range(15):
                store.seed_app(tmp_path)
        except Exception as exc:  # noqa: BLE001 - any failure is the bug
            errors.append(exc)

    def read():
        while not stop.is_set():
            try:
                conn = store.connect(tmp_path / "app.db")
                assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0
                conn.close()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    readers = [threading.Thread(target=read) for _ in range(3)]
    resetters = [threading.Thread(target=reset) for _ in range(4)]
    for t in readers + resetters:
        t.start()
    for t in resetters:
        t.join()
    stop.set()
    for t in readers:
        t.join()
    assert errors == []


def test_a_request_caught_by_a_reset_gets_a_retry_notice_not_a_500(make_client):
    client = make_client()

    def stale(*_a, **_k):
        raise sqlite3.OperationalError("attempt to write a readonly database")

    client.application.view_functions["notes"] = stale  # the endpoint behind /notes
    response = client.post("/notes", data={"body": "x"})
    assert response.status_code == 503 and "Reload the page" in text(response)


def test_data_from_an_older_version_is_reseeded(tmp_path):
    """A checkout updated from a version without vouchers must not fail with 'no such table'."""
    create_app(tmp_path).test_client()
    conn = store.connect(tmp_path / "app.db")
    with conn:
        conn.execute("DROP TABLE credit_log")
    conn.close()
    client = create_app(tmp_path).test_client()
    checks._login(client)
    assert client.get("/account").status_code == 200


@pytest.mark.parametrize("path", ["/invoices", "/notes", "/account", "/help", "/admin"])
def test_quillbook_pages_have_one_banner_and_scrollable_tables_are_focusable(make_client, path):
    # The lab bar is a nav, so Quillbook's own header is the only banner landmark (found with axe-core).
    html = make_client().get(path).get_data(as_text=True)
    assert html.count("<header") == 1
    assert html.count("<table") == html.count('class="qb-scroll" role="region"')
