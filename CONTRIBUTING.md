# Contributing

Thanks for helping. BreachLab is a teaching tool, so clarity matters more than cleverness.

## Set up

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest                  # must be green before you start
ruff check . && ruff format --check .
```

## What is useful

- **Bugs**: a challenge that cannot be solved, a flag that fires wrongly, a fix test that passes a
  broken fix or rejects a sound one. Include the challenge id and the steps.
- **Honest docs**: anything in the README that does not match what the app does.
- **Platform reports**: the lab is tested on macOS and Linux; a note about Windows or other browsers is welcome.
- **New challenges**: open an issue first so we can agree the bug class fits (the roadmap in the README lists candidates).

## Rules for a challenge

Every challenge needs all of these, and CI checks them:

1. A small vulnerable function in `breachlab/vulnerable/` and the same function fixed in `breachlab/solutions/`, with the explanation (why it was vulnerable, why the fix works, the general pattern) in the docstring.
2. A story, goal and three hints in `breachlab/challenges.py`.
3. Automatic detection of the real attack (no flag for a harmless request), and a check in `breachlab/checks.py` that replays the attack and also verifies the feature still works.
4. A test in `fix_tests/` that is red on the vulnerable code and green on the fix, and tests in `tests/` proving the hole is exploitable and then closed, including a few plausible half-fixes that must still fail.

## Safety rails are not optional

Do not weaken the loopback-only bind, the Host and cross-site checks, or the no-outbound-connection
sandbox. A change that touches them needs a test in `tests/test_lab.py`.

## Pull requests

Keep them small, add a line to `CHANGELOG.md` under Unreleased, and make sure `pytest` and `ruff` pass.

## Regenerating the demo GIF

```bash
python -m breachlab --port 4162 --no-reload &
BREACHLAB_URL=http://127.0.0.1:4162 node e2e/demo.cjs     # needs the e2e/ dependencies installed
ffmpeg -i e2e/out/demo.webm -vf "fps=10,scale=800:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96[p];[b][p]paletteuse=dither=bayer:bayer_scale=4" docs/demo.gif
```
