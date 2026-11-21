"""The lab around the app: progress, hints, fix checking, reset, and the safety rails."""

import socket

import pytest

from breachlab import store
from breachlab.__main__ import loopback_address, main
from breachlab.app import SANDBOX_NOTICE, is_external, is_loopback_host
from breachlab.challenges import CHALLENGES


def text(response):
    return response.get_data(as_text=True)


# ---- lab pages -----------------------------------------------------------------------


def test_progress_page_lists_every_challenge(make_client):
    page = text(make_client(login=False).get("/lab"))
    assert all(c.title in page for c in CHALLENGES)
    assert "0 of 10 flags" in page and "never be deployed" in page


@pytest.mark.parametrize("challenge", CHALLENGES, ids=lambda c: c.id)
def test_challenge_page_shows_story_hints_and_fix_instructions(challenge, make_client):
    page = text(make_client(login=False).get(f"/lab/c/{challenge.id}"))
    assert page.count("<details>") == 3
    assert f"breachlab/vulnerable/{challenge.id}.py" in page
    assert f"pytest fix_tests -k {challenge.id}" in page
    assert "Why this fix works" in page


def test_progress_page_says_when_the_reference_fixes_are_running(make_client):
    assert "running the reference fixes" in text(make_client("solutions", login=False).get("/lab"))
    assert "running the reference fixes" not in text(make_client("vulnerable", sqli="solutions").get("/lab"))


def test_unknown_challenge_is_a_404(make_client):
    client = make_client(login=False)
    assert client.get("/lab/c/nope").status_code == 404
    assert client.post("/lab/c/nope/verify").status_code == 404


def test_capturing_a_flag_shows_a_banner_once_and_updates_progress(make_client):
    client = make_client()
    first = text(client.get("/invoices/2001"))
    assert "Flag captured" in first and "1 of 10 flags" in first
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
    assert "1 of 10 flags" in text(again.test_client().get("/lab"))


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


def test_internal_keys_are_refused_to_browsers(make_client, captured):
    response = make_client().get("/internal/keys")
    assert response.status_code == 403 and "qb-billing" not in text(response)
    assert captured() == set()


# ---- safety rails ---------------------------------------------------------------------


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "::", "example.com", ""])
def test_refuses_to_bind_anything_but_loopback(host, capsys):
    with pytest.raises(ValueError):
        loopback_address(host)
    with pytest.raises(SystemExit) as exit_info:
        main(["--host", host])
    assert "Refusing to bind" in str(exit_info.value)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "127.0.0.2"])
def test_accepts_loopback_bind_addresses(host):
    assert loopback_address(host)


def test_non_local_clients_are_refused(make_client):
    client = make_client(login=False)
    assert client.get("/lab", environ_base={"REMOTE_ADDR": "192.168.1.50"}).status_code == 403
    assert client.get("/lab", environ_base={"REMOTE_ADDR": "127.0.0.1"}).status_code == 200


@pytest.mark.parametrize("host", ["evil.example", "evil.example:4160", "127.0.0.1.evil.example", "192.168.1.10:4160"])
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
        ("javascript:alert(1)", True), ("http://localhost/invoices", False), ("/invoices?q=a", False),
        ("/", False), ("invoices", False), ("", False),
    ],
)  # fmt: skip
def test_is_external(target, expected):
    assert is_external(target, "localhost") is expected
