# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-21

First release.

### Added

- Quillbook, a fake notes-and-invoices app (Flask, SQLite, server-rendered) with ten deliberately
  vulnerable functions in `breachlab/vulnerable/`: SQL injection, reflected XSS, stored XSS, IDOR,
  path traversal, open redirect, mass assignment, CSRF, forged JWT (`alg: none` and a weak HS256
  secret) and SSRF.
- Lab pages: challenge list with progress, one page per challenge with story, goal, three hints,
  flag status, fix instructions, a "Check my fix" button and the reference fix behind a spoiler.
- Automatic flag detection on the server for eight challenges, and through an `alert()` hook in
  `static/lab.js` for the two XSS challenges.
- Reference fixes in `breachlab/solutions/`, each with a docstring explaining why the hole existed,
  why the fix works and the secure pattern. `python -m breachlab --fixed` serves them.
- `breachlab/checks.py`: per challenge, an attack replay and a feature regression check. Used by
  `fix_tests/` (the learner's tests), by `tests/` and by the "Check my fix" button.
- Reset buttons for app data and for progress.
- Safety rails: loopback-only bind, per-request client and Host checks, sandboxed SSRF fetch with no
  outbound connections, traversal fenced into the lab's data folder, same-origin lab actions.
- Test suite (`pytest`) and a Playwright walkthrough (`e2e/solve.cjs`) that solves all ten challenges
  in Chromium and verifies they fail on the reference fixes. GitHub Actions runs lint, tests and both
  walkthroughs.

### Notes for the next contributor

- A challenge is five things with the same id: an entry in `challenges.py`, a module in
  `vulnerable/`, a module in `solutions/`, a function in `checks.CHECKS`, and the route in `app.py`
  that calls the module and awards the flag. `tests/test_challenges.py` is parametrized over
  `CHALLENGES` and will fail loudly if one of them is missing.
- The checks in `checks.py` are themselves under test: `HALF_FIXES` and `SOUND_ALTERNATIVES` in
  `tests/test_challenges.py` hold fixes a check must reject or accept. When you add an attack
  variation, add the half-fix that motivated it there.
- `fix_tests/` is meant to fail on a clean checkout (it tests `vulnerable/`). Do not add it to
  pytest's `testpaths`; CI asserts both that it fails on vulnerable code and passes with
  `BREACHLAB_IMPL=solutions`.
- The SSRF fetch runs the inner request through `app.test_client()` inside a fresh app context.
  Without the fresh context the inner request overwrote `g.user` of the outer one (Flask reuses the
  active app context); `test_import_preview_keeps_the_user_signed_in` guards this.
- Werkzeug strips tabs from, and percent-encodes backslashes in, `Location` headers. That is why
  `/\t/evil.example` is a working open-redirect payload here and `/\evil.example` is not.
- Screenshots in `docs/screenshots/` come from the running app via Playwright (`e2e/solve.cjs`
  writes a full set to `e2e/out/`). Retake them after UI changes.
- Not done yet, see the Roadmap in the README: attacker-page helper for CSRF, RS256/HS256 key
  confusion, more bug classes, Windows verification.

[0.1.0]: https://github.com/Habibeyilmazz/breachlab/releases/tag/v0.1.0
