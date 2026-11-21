"""Every challenge is exploitable on the vulnerable code and closed on the reference fixes."""

import hashlib
import hmac
import re

import pytest

from breachlab import checks
from breachlab.app import load_impl
from breachlab.challenges import CHALLENGES

IDS = [c.id for c in CHALLENGES]
# These two flags are captured by script running in a real browser (see e2e/solve.mjs);
# here the attack is proven by the payload arriving unescaped in the HTML.
BROWSER_DETECTED = {"reflected_xss", "stored_xss"}


def test_there_are_ten_challenges_with_three_hints_each():
    assert len(CHALLENGES) == len(set(IDS)) == len(checks.CHECKS) == 10
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
