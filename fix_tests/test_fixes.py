"""The provided fix tests: one per challenge, each failing until its hole is closed.

    pytest fix_tests -k sqli      # the test for one challenge
    pytest fix_tests              # all ten; a fresh checkout shows ten failures, your to-do list

They test the code in breachlab/vulnerable/ (your working copy). Set BREACHLAB_IMPL=solutions
to run them against the reference fixes instead.
"""

import os

import pytest

from breachlab import checks
from breachlab.app import load_impl
from breachlab.challenges import CHALLENGES


@pytest.mark.parametrize("challenge_id", [c.id for c in CHALLENGES])
def test_fixed(challenge_id):
    report = checks.run(challenge_id, load_impl(os.environ.get("BREACHLAB_IMPL", "vulnerable")))
    assert report.attack is None, f"The attack still works: {report.attack}"
    assert report.broken is None, f"Something legitimate broke: {report.broken}"
