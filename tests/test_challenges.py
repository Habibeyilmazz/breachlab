"""Every challenge is exploitable on the vulnerable code and closed on the reference fixes."""

import hashlib
import hmac
import itertools
import re
import threading
import time
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from markupsafe import Markup

from breachlab import checks
from breachlab.app import is_loopback_host, load_impl
from breachlab.challenges import BY_ID, CHALLENGES, UNSIGNED_ADMIN_TOKEN

IDS = [c.id for c in CHALLENGES]
# These two flags are captured by script running in a real browser (see e2e/solve.cjs);
# here the attack is proven by the payload arriving unescaped in the HTML.
BROWSER_DETECTED = {"reflected_xss", "stored_xss"}


def test_there_are_eleven_challenges_with_three_hints_each():
    assert len(CHALLENGES) == len(set(IDS)) == len(checks.CHECKS) == 11
    assert all(len(c.hints) == 3 and all(c.hints) for c in CHALLENGES)


@pytest.mark.parametrize("challenge_id", IDS)
def test_vulnerable_code_is_exploitable_and_the_flag_is_captured(challenge_id, make_client, captured):
    attack, _broken = checks.CHECKS[challenge_id](make_client("vulnerable"))
    assert attack is not None
    if challenge_id not in BROWSER_DETECTED:
        assert captured() == {challenge_id}


@pytest.mark.parametrize("challenge_id", IDS)
def test_reference_fix_blocks_the_attack_and_keeps_the_feature(challenge_id, make_client, captured):
    attack, broken = checks.CHECKS[challenge_id](make_client("solutions"))
    assert (attack, broken) == (None, None)
    assert captured() == set()


@pytest.mark.parametrize("challenge_id", IDS)
def test_fixing_one_challenge_passes_its_check_while_the_rest_stay_vulnerable(challenge_id, make_client):
    attack, broken = checks.CHECKS[challenge_id](make_client("vulnerable", **{challenge_id: "solutions"}))
    assert (attack, broken) == (None, None)


def test_each_open_redirect_trick_leaves_the_site_on_vulnerable_code(make_client):
    app = make_client("vulnerable", login=False).application
    for target in ("https://evil.example/", "//evil.example/", "/\t/evil.example/", "https:evil.example"):
        location = checks._login(app.test_client(), target).headers["Location"]
        assert checks._is_external(location), (target, location)


def test_weak_jwt_secret_can_be_cracked_with_the_shipped_wordlist(make_client, captured):
    client = make_client("vulnerable")
    token = re.search(r"eyJ[\w-]+\.[\w-]+\.[\w-]*", client.get("/account").get_data(as_text=True)).group(0)
    signing_input, _, signature = token.rpartition(".")
    cracked = [
        word
        for word in checks.WORDLIST.read_text().split()
        if checks._b64(hmac.new(word.encode(), signing_input.encode(), hashlib.sha256).digest()) == signature
    ]
    assert cracked == ["sunshine"]
    forged = checks._forge(b"sunshine", "HS256", {"sub": "alice", "role": "admin"})
    report = client.get("/api/admin/report", headers={"Authorization": f"Bearer {forged}"})
    assert report.status_code == 200 and "BL{" in report.get_json()["flag"]
    assert captured() == {"weak_jwt"}


def test_the_token_spelled_out_in_the_last_jwt_hint_is_the_answer(make_client, captured):
    assert UNSIGNED_ADMIN_TOKEN in BY_ID["weak_jwt"].hints[2]
    bearer = {"Authorization": f"Bearer {UNSIGNED_ADMIN_TOKEN}"}
    assert make_client("solutions").get("/api/admin/report", headers=bearer).status_code == 401
    assert make_client("vulnerable").get("/api/admin/report", headers=bearer).status_code == 200
    assert captured() == {"weak_jwt"}


def test_a_genuine_admin_token_is_not_a_forgery(make_client, captured):
    """After the mass assignment challenge alice is a real admin: her own token must not capture the JWT flag."""
    client = make_client("vulnerable")
    checks._save_account(client, display_name="Alice Moreau", email="alice@quillbook.test", role="admin")
    token = re.search(r"eyJ[\w-]+\.[\w-]+\.[\w-]*", client.get("/account").get_data(as_text=True)).group(0)
    report = client.get("/api/admin/report", headers={"Authorization": f"Bearer {token}"})
    assert report.status_code == 200 and "flag" not in report.get_json() and "forge" in report.get_json()["note"]
    assert captured() == {"mass_assignment"}
    forged = {"Authorization": f"Bearer {UNSIGNED_ADMIN_TOKEN}"}  # the real attack still counts for an admin alice
    assert "flag" in client.get("/api/admin/report", headers=forged).get_json()
    assert captured() == {"mass_assignment", "weak_jwt"}


def test_traversal_flag_needs_a_file_not_a_404(make_client, captured):
    client = make_client("vulnerable")
    for name in ("../nothing-here.txt", "..", "../private"):
        assert client.get("/exports/download", query_string={"file": name}).status_code == 404
    assert captured() == set()
    assert client.get("/exports/download", query_string={"file": "../private/payroll-2026.txt"}).status_code == 200
    assert captured() == {"path_traversal"}


@pytest.mark.parametrize("token", ["", "abc", "a.b.c", "e30.e30.", "W10.W10.", "!!.!!.!!"])
@pytest.mark.parametrize("package", ["vulnerable", "solutions"])
def test_malformed_tokens_are_rejected_without_crashing(make_client, package, token):
    response = make_client(package).get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_sql_errors_are_shown_on_the_vulnerable_search(make_client):
    page = make_client("vulnerable").get("/invoices?q=O'Brien").get_data(as_text=True)
    assert "Database error" in page


def test_union_injected_rows_render_without_crashing(make_client):
    payload = "' UNION SELECT id, username, 'n/a', password_hash FROM users--"
    response = make_client("vulnerable").get("/invoices", query_string={"q": payload})
    assert response.status_code == 200 and "scrypt:" in response.get_data(as_text=True)


@pytest.mark.parametrize("challenge_id", IDS)
def test_reference_fix_explains_itself(challenge_id):
    doc = getattr(load_impl("solutions"), challenge_id).__doc__
    for heading in ("Why the hole existed", "Why this fix works", "The secure pattern"):
        assert heading in doc


# ---- the checks must not be fooled by half-fixes, nor reject sound alternatives ----------


def _with(make_client, challenge_id, **functions):
    """A lab on the reference fixes, except one challenge whose functions are replaced."""
    impl = load_impl("solutions")
    setattr(impl, challenge_id, SimpleNamespace(**functions))
    client = make_client("solutions")
    client.application.config["IMPL"] = impl
    return checks.CHECKS[challenge_id](client)


def _escape_first_quote(db, user_id, query):
    escaped = query.replace("'", "''", 1)
    sql = f"SELECT id, customer, amount_cents, status FROM invoices WHERE owner_id = ? AND customer LIKE '%{escaped}%'"
    return db.execute(sql, (user_id,)).fetchall()


def _strip_script_tags(body):
    return Markup(re.sub(r"(?is)<script.*?</script>", "", body).replace("\n", "<br>"))


def _refuse_loopback_only(url):
    return urlsplit(url).scheme in ("http", "https") and not is_loopback_host(urlsplit(url).hostname or "")


def _claim_but_ignore_the_answer(db, user_id, code, partner_confirms):
    """Adds the atomic claim, but still credits when the claim found the voucher already taken."""
    voucher = db.execute("SELECT cents, redeemed_by FROM vouchers WHERE code = ?", (code,)).fetchone()
    if voucher is None or voucher["redeemed_by"] is not None or not partner_confirms(code):
        return None
    with db:
        db.execute("UPDATE vouchers SET redeemed_by = ? WHERE code = ? AND redeemed_by IS NULL", (user_id, code))
        db.execute("UPDATE users SET credit_cents = credit_cents + ? WHERE id = ?", (voucher["cents"], user_id))
    return voucher["cents"]


_arrivals = itertools.count()


def _check_again_just_before_the_write(db, user_id, code, partner_confirms):
    """Narrows the window to microseconds, but check and write are still two steps."""
    if not partner_confirms(code):
        return None
    time.sleep(0.02 * (next(_arrivals) % 4))  # scheduling jitter: the four requests reach the check 20 ms apart
    voucher = db.execute("SELECT cents, redeemed_by FROM vouchers WHERE code = ?", (code,)).fetchone()
    if voucher is None or voucher["redeemed_by"] is not None:
        return None
    with db:
        db.execute("UPDATE vouchers SET redeemed_by = ? WHERE code = ?", (user_id, code))
        db.execute("UPDATE users SET credit_cents = credit_cents + ? WHERE id = ?", (voucher["cents"], user_id))
    return voucher["cents"]


def test_a_narrowed_race_window_fails_the_check_even_when_requests_do_not_arrive_together(make_client):
    attack, _broken = _with(make_client, "race_condition", redeem_voucher=_check_again_just_before_the_write)
    assert attack is not None


_one_at_a_time = threading.Lock()


def _redeem_under_a_lock(*args):
    with _one_at_a_time:
        return load_impl("vulnerable").race_condition.redeem_voucher(*args)


HALF_FIXES = {
    "race_condition": {"redeem_voucher": _claim_but_ignore_the_answer},
    "sqli": {"search_invoices": _escape_first_quote},
    "stored_xss": {"render_note": _strip_script_tags},
    "reflected_xss": {"results_heading": lambda q, n: Markup(f"{n} for {q.replace('<script', '')}")},
    "csrf": {"is_request_genuine": lambda session, sent: bool(sent) and session.startswith(sent)},
    "ssrf": {"is_allowed_url": _refuse_loopback_only},
    "mass_assignment": {
        "profile_changes": lambda form: {k: v for k, v in form.items() if k not in ("role", "credit_cents")}
    },
    "open_redirect": {"redirect_target": lambda url: "/invoices" if url.startswith("http") else url or "/invoices"},
    "path_traversal": {"export_path": lambda base, name: None if name.startswith("..") else base / name},
    "idor": {"load_invoice": lambda db, uid, iid: db.execute("SELECT * FROM invoices WHERE id = ?", (iid,)).fetchone()},
}


@pytest.mark.parametrize("challenge_id", HALF_FIXES)
def test_half_fixes_do_not_pass_the_check(challenge_id, make_client):
    attack, _broken = _with(make_client, challenge_id, **HALF_FIXES[challenge_id])
    assert attack is not None


SOUND_ALTERNATIVES = {
    "race_condition": {"redeem_voucher": _redeem_under_a_lock},  # closes it, if only within one process
    "reflected_xss": {"results_heading": lambda q, n: Markup("<b>{}</b>: {} found").format(q, n)},
    "stored_xss": {"render_note": lambda body: Markup('<span style="white-space: pre-line">{}</span>').format(body)},
    "open_redirect": {"redirect_target": lambda url: url if url in ("/invoices", "/notes?from=login") else "/invoices"},
    "mass_assignment": {"profile_changes": lambda form: {"display_name": form["display_name"], "email": form["email"]}},
}


@pytest.mark.parametrize("challenge_id", SOUND_ALTERNATIVES)
def test_sound_alternative_fixes_pass_the_check(challenge_id, make_client):
    assert _with(make_client, challenge_id, **SOUND_ALTERNATIVES[challenge_id]) == (None, None)


def test_a_crash_in_patched_code_fails_the_check_instead_of_the_lab():
    impl = load_impl("solutions")
    impl.idor = SimpleNamespace()  # no load_invoice at all
    report = checks.run("idor", impl)
    assert not report.ok


# ---- reference fixes: edge cases --------------------------------------------------------


@pytest.mark.parametrize(
    "url, allowed",
    [
        ("http://1.1.1.1/a", True), ("https://8.8.8.8:8443/a", True),
        ("http://127.0.0.1/", False), ("http://localhost/", False), ("http://[::1]/", False),
        ("http://2130706433/", False), ("http://127.1/", False), ("http://0x7f.0.0.1/", False),
        ("http://0.0.0.0/", False), ("http://[::ffff:127.0.0.1]/", False), ("http://[::ffff:10.0.0.1]/", False),
        ("http://10.0.0.5/", False), ("http://192.168.1.1/", False), ("http://172.16.0.9/", False),
        ("http://169.254.169.254/latest/meta-data/", False), ("http://[fd00::1]/", False), ("http://[fe80::1]/", False),
        ("http://224.0.0.1/", False), ("http://[ff02::1]/", False),
        ("ftp://1.1.1.1/", False), ("file:///etc/hosts", False), ("http://", False), ("http://[bad/", False), ("", False),
        ("http://1.1.1.1:notaport/", False),
    ],
)  # fmt: skip
def test_reference_ssrf_fix_only_allows_public_addresses(url, allowed):
    assert load_impl("solutions").ssrf.is_allowed_url(url) is allowed


@pytest.mark.parametrize(
    "target, expected",
    [
        ("/notes", "/notes"), ("/invoices?q=a&b=1", "/invoices?q=a&b=1"), ("", "/invoices"),
        ("https://evil.example", "/invoices"), ("//evil.example", "/invoices"), ("/\\evil.example", "/invoices"),
        ("\\\\evil.example", "/invoices"), ("/\t/evil.example", "/invoices"), ("https:evil.example", "/invoices"),
        ("javascript:alert(1)", "/invoices"), ("notes", "/invoices"), (" /notes", "/invoices"),
    ],
)  # fmt: skip
def test_reference_open_redirect_fix_only_allows_local_paths(target, expected):
    assert load_impl("solutions").open_redirect.redirect_target(target) == expected


@pytest.mark.parametrize("name", ["../private/payroll-2026.txt", "/etc/hosts", "a\x00b", "", ".", "missing.txt"])
def test_reference_path_fix_returns_nothing_for_bad_names(name, tmp_path):
    (tmp_path / "exports").mkdir()
    (tmp_path / "exports" / "invoice-1.txt").write_text("ok")
    (tmp_path / "private").mkdir()
    (tmp_path / "private" / "payroll-2026.txt").write_text("secret")
    export_path = load_impl("solutions").path_traversal.export_path
    assert export_path(tmp_path / "exports", name) is None
    assert export_path(tmp_path / "exports", "invoice-1.txt") == (tmp_path / "exports" / "invoice-1.txt").resolve()


@pytest.mark.parametrize("package", ["vulnerable", "solutions"])
def test_absurdly_nested_token_is_rejected_not_a_crash(make_client, package):
    nested = checks._b64(("[" * 20000 + "]" * 20000).encode())
    for token in (f"{nested}.e30.", f"{checks._b64(b'{}')}.{nested}."):
        response = make_client(package).get("/api/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401


def test_reference_csrf_fix_never_matches_an_empty_session_token():
    genuine = load_impl("solutions").csrf.is_request_genuine
    assert genuine("tok", "tok") is True
    assert (genuine("", ""), genuine("tok", ""), genuine("tok", "to"), genuine("tok", "tokk")) == (False,) * 4
    assert genuine("tok", "tök") is False  # non-ASCII input must not raise


# ---- race condition -----------------------------------------------------------------------


def test_redeeming_a_voucher_once_is_no_race(make_client, captured):
    client = make_client("vulnerable")
    client.application.config["PARTNER_SECONDS"] = 0
    checks._redeem(client, "QB-WELCOME-10")
    again = client.get(checks._redeem(client, "QB-WELCOME-10").headers["Location"]).get_data(as_text=True)
    assert "already been used" in again and again.count("QB-WELCOME-10</td>") == 1
    assert checks._alice_record(client)["credit_cents"] == 3500
    assert captured() == set()


def test_a_fix_that_skips_the_voucher_partner_is_not_accepted(make_client):
    def no_partner(db, user_id, code, _partner_confirms):
        return load_impl("solutions").race_condition.redeem_voucher(db, user_id, code, lambda _code: True)

    attack, broken = _with(make_client, "race_condition", redeem_voucher=no_partner)
    assert attack is None and "withdrawn" in broken


def test_the_race_hint_is_the_answer():
    assert "QB-WELCOME-10" in BY_ID["race_condition"].hints[2] and "Promise.all" in BY_ID["race_condition"].hints[2]
