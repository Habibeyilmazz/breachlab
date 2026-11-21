# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- Any website open in the learner's browser could drive the deliberately vulnerable app: a link
  to `/help?q=<script>…` ran script in the lab's origin (cookies are `SameSite=Lax`, so a top-level
  navigation is signed in), and a cross-site iframe of `/lab` passed the same-origin check on the
  reset button. Requests marked `Sec-Fetch-Site: cross-site` now get a 403 and every response
  carries `X-Frame-Options: DENY`. Tests: `test_other_websites_cannot_drive_the_lab`,
  `test_pages_cannot_be_framed`; also checked in Chromium from a page on `localhost:4163`.
- CI pins every action to a full commit SHA (tag in a comment) and checks out with
  `persist-credentials: false`, so later steps never see the job token.

### Added

- Mallory's site, a built-in attacker website for the CSRF challenge. It was the only challenge that
  sent the learner off to write a file and start a second server. Now the challenge page has a box for
  the attacker page; "Save page" stores it in `.breachlab/attacker.html` and the lab serves it at `/`
  on the next port (`--attacker-port`, default `--port` + 1), a different origin but the same site.
  It runs in a thread of the serving process (restarted with it by the reloader) with the lab's
  loopback, Host and cross-site rails. A busy port does not stop the lab: the page then shows the
  `python3 -m http.server` workaround. Hints 2 and 3 point at it. `e2e/solve.cjs` now solves CSRF
  through it instead of running its own server. Tests: `tests/test_attacker.py`, plus a check in
  `test_saving_a_syntax_error_does_not_kill_the_server` that the site comes back after a reload.
- A dark theme for the lab pages and Quillbook, picked from the system's `prefers-color-scheme`.
  Colours in `static/style.css` are tokens on `:root`; `--night` is for surfaces that stay dark in
  both themes (lab bar, code blocks).

### Fixed

- Keyboard focus rings were amber on light paper (about 2:1 contrast). They are ink on light
  backgrounds and amber on dark ones.
- The progress squares in the lab bar were 18px with 5px gaps, under the 24px target size. They are
  20px with 6px gaps.
- At phone width the challenge number sat on a line of its own above each title, and the invoice
  table split amounts, column headers and status words mid-word (`$1,240.` / `00`).

- The forged JWT flag was captured without forging anything: after the mass assignment challenge
  alice is a real admin, and the token her account page shows opened `/api/admin/report`. A token
  Quillbook itself issued to a real admin now gets the report with a note and no flag.
- The path traversal flag was awarded for any path outside `exports/`, even when the answer was a
  404. It now needs a file that is actually served, or the sandbox notice for a path outside the
  lab's data folder.
- Saving a patch that does not import (a syntax error) no longer ends the server: it serves the
  traceback as a plain page and recovers on the next save. An exception raised by patched code is
  named on the 500 page and in the fix check.
- Odd input no longer ends in a 500: a `next` address that cannot be a `Location` header
  (`http://[`, a bad port, a line break) is a 400 after sign-in, an export name longer than the file
  system allows is a 404, and the XSS beacon ignores JSON that is not an object.

### Changed

- The last hint really is the answer, as the README says: the CSRF hint holds the whole attacker
  page, the JWT hint the finished unsigned token and curl command. The stored XSS hint no longer
  asks for a reload that hid the flag banner.
- The JWT fix stage says that the `SECRET` has to change too, not only `verify`.
- README: run the fix test in a second terminal with the virtual environment activated.
- `e2e/package-lock.json` is committed and CI installs the walkthrough with `npm ci`.

### Notes for the next contributor

- Werkzeug's `make_server` calls `sys.exit(1)` (not raise) when a port is busy; `start_attacker` in
  `__main__.py` catches `SystemExit` for that reason. Tests that start real servers keep to ports
  4165-4169 and pass `--attacker-port` so the default `--port` + 1 does not leave that range.
- Design pass: checked desktop and 390px, light and dark, by screenshot, plus Tab order on the
  challenge list. README screenshots were retaken from the running app (vulnerable lab with ten
  flags, four marked fixed with "Check my fix" on a `--fixed` server sharing the same checkout).
- First-run check done from a fresh clone on macOS, Python 3.12: quickstart, every third hint
  followed literally in Chromium, patch / "Check my fix" / `pytest fix_tests -k`, a syntax error and
  recovery, `--fixed`, `--host ::1`, `--host localhost`, a refused `--host 0.0.0.0`, a busy port,
  and the README's e2e steps all work as written.
- Security pass (2026-11-22): `pip-audit -r requirements-dev.txt` and `npm audit` in `e2e/` found
  nothing; no secrets or personal data in git history; reference fixes in `solutions/` reviewed, no
  new holes found. The rails' remaining gaps are the ones listed in the README (DNS lookups by the
  SSRF fix, Safari before 16.4 without `Sec-Fetch-Site`). When you bump an action, update the SHA
  and the tag comment together (`gh api repos/<owner>/<action>/commits/<tag> --jq .sha`).
- Flag detection is where the bugs were. When you add a challenge, ask what else in the app can
  reach its "success" state legitimately (another challenge's side effect, a failed request) and
  add a test like `test_a_genuine_admin_token_is_not_a_forgery`.
- Still open and deliberate, see Known limits in the README: XSS flags need `alert()`/`confirm()`/
  `prompt()`, no RS256/HS256 confusion, the learner serves the CSRF attacker page with
  `python3 -m http.server`, the reference SSRF fix resolves host names, Windows is unverified.

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
