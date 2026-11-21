"""Mallory's site: the built-in attacker origin for the CSRF challenge."""

import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

from breachlab.__main__ import main
from breachlab.app import PACKAGE_DIR
from breachlab.attacker import MAX_PAGE, STARTER_PAGE, create_attacker_app, page_path

ATTACK = (
    '<form method="post" action="http://127.0.0.1:4160/account"><input name="display_name" value="Alice">'
    '<input name="email" value="mallory@evil.test"></form><script>document.forms[0].submit()</script>'
)


@pytest.fixture
def lab(make_client):
    client = make_client(login=False)
    client.application.config["ATTACKER_PORT"] = 4161
    return client


def test_the_page_saved_in_the_lab_is_served_on_mallorys_site(lab, tmp_path):
    mallory = create_attacker_app(tmp_path).test_client()
    assert mallory.get("/").get_data(as_text=True) == STARTER_PAGE
    saved = lab.post("/lab/attacker", data={"page": ATTACK})
    assert saved.status_code == 302 and saved.headers["Location"] == "/lab/c/csrf?saved=1#mallory"
    response = mallory.get("/")
    assert response.get_data(as_text=True) == ATTACK and response.mimetype == "text/html"
    assert mallory.get("/phish").status_code == 404


def test_the_csrf_page_links_to_mallorys_site_on_the_host_being_browsed(lab):
    page = lab.get("/lab/c/csrf", headers={"Host": "localhost:4160"}).get_data(as_text=True)
    assert 'href="http://localhost:4161/"' in page and "Win a free coffee!" in page
    lab.post("/lab/attacker", data={"page": ATTACK})
    page = lab.get("/lab/c/csrf?saved=1").get_data(as_text=True)
    assert "mallory@evil.test" in page and "Saved." in page
    assert "Mallory's site" not in lab.get("/lab/c/sqli").get_data(as_text=True)


def test_without_mallorys_site_the_page_explains_the_workaround(make_client):
    page = make_client(login=False).get("/lab/c/csrf").get_data(as_text=True)
    assert "Mallory's site is not running" in page and "python3 -m http.server 8001" in page


def test_saving_the_page_is_a_same_origin_lab_action_with_a_size_limit(lab, tmp_path):
    evil = {"Origin": "http://127.0.0.1:4161"}
    assert lab.post("/lab/attacker", data={"page": "x"}, headers=evil).status_code == 403
    assert lab.post("/lab/attacker", data={"page": "x" * (MAX_PAGE + 1)}).status_code == 413
    assert create_attacker_app(tmp_path).test_client().get("/").get_data(as_text=True) == STARTER_PAGE


def test_reset_everything_forgets_the_page_and_reset_data_keeps_it(lab, tmp_path):
    lab.post("/lab/attacker", data={"page": ATTACK})
    lab.post("/lab/reset", data={"what": "data"})
    assert (tmp_path / "attacker.html").read_text() == ATTACK
    lab.post("/lab/reset", data={"what": "everything"})
    assert not (tmp_path / "attacker.html").exists()


def test_mallorys_site_keeps_the_loopback_rails(tmp_path):
    mallory = create_attacker_app(tmp_path).test_client()
    assert mallory.get("/", headers={"Host": "evil.example"}).status_code == 403
    assert mallory.get("/", environ_base={"REMOTE_ADDR": "192.168.1.50"}).status_code == 403
    assert mallory.get("/", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert mallory.get("/", headers={"Host": "127.0.0.1:4161"}).status_code == 200


def test_attacker_port_must_differ_from_the_lab_port():
    with pytest.raises(SystemExit) as exit_info:
        main(["--port", "4166", "--attacker-port", "4166"])
    assert "must differ" in str(exit_info.value)


def _get(url):
    for _attempt in range(50):
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                return response.read().decode()
        except urllib.error.HTTPError as error:
            return error.read().decode()
        except OSError:
            time.sleep(0.2)
    raise AssertionError(f"nothing answered at {url}")


@pytest.mark.parametrize("busy", [False, True], ids=["free", "busy"])
def test_the_server_runs_mallorys_site_on_the_next_port_or_carries_on_without_it(busy, tmp_path):
    port = 4167
    shutil.copytree(PACKAGE_DIR, tmp_path / "breachlab", ignore=shutil.ignore_patterns("__pycache__"))  # own data dir
    blocker = socket.socket()
    if busy:
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # the "free" run can leave the port in TIME_WAIT
        blocker.bind(("127.0.0.1", port + 1))
        blocker.listen()
    server = subprocess.Popen(
        [sys.executable, "-m", "breachlab", "--no-reload", "--port", str(port)],
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        page = _get(f"http://127.0.0.1:{port}/lab/c/csrf")
        if busy:
            assert "is not running" in page
        else:
            assert f'href="http://127.0.0.1:{port + 1}/"' in page
            assert STARTER_PAGE == _get(f"http://127.0.0.1:{port + 1}/")
    finally:
        server.terminate()
        output = server.communicate(timeout=10)[0]
        blocker.close()
    assert ("could not start" in output) is busy


def test_flask_debug_in_the_environment_does_not_turn_on_the_werkzeug_debugger(tmp_path):
    """The debugger's console runs Python and sits in front of the Host and cross-site checks."""
    port = 4164
    shutil.copytree(PACKAGE_DIR, tmp_path / "breachlab", ignore=shutil.ignore_patterns("__pycache__"))
    server = subprocess.Popen(
        [sys.executable, "-m", "breachlab", "--no-reload", "--port", str(port), "--attacker-port", "4163"],
        cwd=tmp_path,
        env={**os.environ, "FLASK_DEBUG": "1"},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _get(f"http://127.0.0.1:{port}/lab")  # wait until it serves
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/console", timeout=5)
        assert error.value.code == 404 and b"Werkzeug Debugger" not in error.value.read()
    finally:
        server.terminate()
        output = server.communicate(timeout=10)[0]
    assert "Debug mode: on" not in output


def test_a_page_with_non_ascii_text_survives_the_round_trip(lab, tmp_path):
    page = "<p>Grüße 😈 日本語</p>"
    assert lab.post("/lab/attacker", data={"page": page}).status_code == 302
    assert page_path(tmp_path).read_bytes() == page.encode("utf-8")
    assert create_attacker_app(tmp_path).test_client().get("/").get_data().decode("utf-8") == page


@pytest.mark.parametrize("flag", ["--port", "--attacker-port"])
@pytest.mark.parametrize("value", ["0", "-1", "65536", "70000"])
def test_ports_outside_the_valid_range_are_a_usage_error_not_a_traceback(flag, value, capsys):
    with pytest.raises(SystemExit) as exit_info:
        main([flag, value])
    assert exit_info.value.code == 2 and "between 1 and 65535" in capsys.readouterr().err
