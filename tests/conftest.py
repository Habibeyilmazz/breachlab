import pytest

from breachlab import checks, store
from breachlab.app import create_app, load_impl


@pytest.fixture
def make_client(tmp_path):
    """Build a fresh lab on throwaway data and return a test client signed in as alice."""

    def make(package="vulnerable", login=True, **overrides):
        client = create_app(tmp_path, load_impl(package, **overrides)).test_client()
        if login:
            checks._login(client)
        return client

    return make


@pytest.fixture
def captured(tmp_path):
    """Return the set of challenge ids whose flag has been captured so far."""

    def read():
        lab = store.connect(tmp_path / "lab.db")
        try:
            return {cid for cid, row in store.progress(lab).items() if row["solved_at"]}
        finally:
            lab.close()

    return read
