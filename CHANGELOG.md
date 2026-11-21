# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Checked (launch pass, round 14)

- Re-verified the launch material: 270 tests pass, CI green on main, README screenshots and demo GIF exist and match
  the eleven challenges, repo description and 16 topics are set, CONTRIBUTING and issue templates are present. Nothing
  needed changing. Still unchecked: Windows, Safari, Lighthouse. Port 4160 is held by a process that is not ours.

### Fixed (reliability pass, round 13)

- The 404 page and the JSON 404 for `/api/` and `/internal/` used Flask's stock "If you entered the URL
  manually..." text. They now say "There is no page at this address." (specific messages such as "No such
  invoice." are untouched). Test: `test_an_unknown_address_gets_plain_wording_not_flasks_stock_text`.
- Tried to break it and found nothing else: ~130 odd GETs (200 KB values, NUL, RTL/emoji, `../`, `1e999`)
  and POSTs (huge bodies, invalid UTF-8, JSON instead of form) against vulnerable and fixed code gave no
  5xx; on a real server on port 4168, 300 concurrent requests, a 70 KB path, a 20 KB query, a bogus
  `Content-Length` and a garbage request line all got clean answers and the server kept serving.
- Two real-server tests (reloader) were racy on a slow CI runner: a response cut off mid-read by a reload,
  and git briefly removing the file being polled. Both now retry; CI went red once on this, then green.
- Not changed: Windows, Safari and Lighthouse remain unchecked. PID 68470 on port 4160 is not ours.

### Added (feature round 12)

- "Start over" on every challenge page. Once a learner had fixed a hole there was no way back to the
  vulnerable code from the lab: "Reset data and progress" cleared the flags but left the patched files, so
  those flags could not be captured again, and a botched patch needed git knowledge to undo. The button
  (with a confirm) runs `git checkout HEAD -- breachlab/vulnerable/<id>.py`, reseeds the sample data (a
  stored payload would otherwise re-award the flag at once) and clears that one challenge's flag and fix
  result; other flags are kept. Outside a git checkout it clears progress and says to undo the file by hand.
  Hidden on a `--fixed` server. Route `POST /lab/c/<id>/restart`, same-origin like every lab action.
- The checkout runs after the response is sent (`call_on_close`): the reloader kills the serving process as
  soon as it sees the file change, and a first version doing it inside the request had its reply cut off
  in Chromium. It uses `git diff-index`, because outside a repository `git diff` silently compares files
  instead of failing (caught by the no-git test).
- Tests: `test_starting_a_challenge_over_restores_its_code_data_and_progress` and
  `test_starting_over_without_git_clears_progress_and_leaves_the_file_alone` (throwaway git repos, never the
  real files), and `test_starting_over_on_a_real_server_answers_then_reloads_the_original_code` (a copied
  checkout, a real server with the reloader on port 4167, Mallory on 4166). Checked by hand in Chromium on
  the real checkout: fix SQL injection, "Check my fix" says Fixed, "Start over", confirm, the note appears,
  and after the reload "Check my fix" says "Not fixed yet" again; light, dark and 390 px.
- Not changed: the 404 page still uses Flask's stock wording; Windows, Safari and Lighthouse remain unchecked.

### Security (security pass, round 11)

- `FLASK_DEBUG=1` in the learner's shell turned on Werkzeug's debugger: `/console` answered with a
  Python console (PIN-protected) from middleware that runs before the loopback Host and cross-site
  checks. The server now calls `app.run(..., debug=False)`, which wins over the environment. Test:
  `test_flask_debug_in_the_environment_does_not_turn_on_the_werkzeug_debugger` (fails without the change).
- README safety rails: a "No debugger" bullet, and an honest note that any page on another localhost
  port is same-site, so other local dev servers could drive the holes too.
- Checked and found clean: `pip-audit` (Flask 3.1.3, Werkzeug 3.1.9, Jinja2 3.1.6, all installed
  packages) and `npm audit` in `e2e/` report nothing; every pinned action SHA matches its tag
  (`gh api`); workflow token is `contents: read` with `persist-credentials: false`; no secrets or
  personal paths in git history. Reference fixes reread; nothing to change.
- `node e2e/solve.cjs` rerun in both modes on port 4162: 11 of 11 flags captured vulnerable, all 11
  attacks blocked and fixes verified with `--fixed`.
- Not changed: the 404 page still uses Flask's stock wording; Windows, Safari and Lighthouse remain unchecked.

### Changed (design pass, round 10)

- Looked at every lab and Quillbook page in Chromium at 1280 px and 390 px, light and dark. No horizontal
  scroll, focus rings visible everywhere tried; most of it was already in good shape, so the changes are small.
- Phones: the lab bar was three rows (name, squares, count) and Quillbook's header four, so about 270 px
  of chrome before any content. Now the BreachLab name, flag count and Challenges link share one row with
  the squares below, and Quillbook's logo and Sign out share one row with the links below.
- "Check my fix" says "Checking…" while the check runs (the race check takes about a second) and ignores a
  second click; the Back button restores it. Checked by `e2e/solve.cjs` on the race challenge.
- Invoice statuses are coloured: paid green, overdue red, due neutral (`data-status` on the pill).
- The demo credentials on the sign-in page no longer break at the hyphen of `alice-demo`.
- README: `exploit.png` retaken (status colours) and a new phone-width screenshot, `docs/screenshots/phone.png`.
- Not changed: the 404 page still uses Flask's stock wording; Windows, Safari and Lighthouse remain unchecked.

### Fixed (first-run review, round 9)

- Fresh clone, README quickstart followed literally on macOS (Python 3.12): install, `pytest`, the
  learner's `pytest fix_tests -k sqli` and `node e2e/solve.cjs` (11 of 11 flags) all work as written.
- The race condition check no longer depends on thread timing. It hands the learner's function a
  connection whose `SELECT`s pause 50 ms, so "check again just before the write" fails every time
  instead of passing by luck; the reference fix and a `threading.Lock` still pass. Test:
  `test_a_narrowed_race_window_fails_the_check_even_when_requests_do_not_arrive_together` (fails without the change).
- `test_the_server_runs_mallorys_site_on_the_next_port_or_carries_on_without_it[busy]` failed in the fresh
  clone on macOS (it passes when rerun): the "free" run leaves port 4168 in `TIME_WAIT`, and the test's blocker socket
  could not bind it. The blocker now sets `SO_REUSEADDR`.
- The seeded payroll file was the one file still written in the platform's default encoding; now UTF-8.

### Security

- Any website open in the learner's browser could drive the deliberately vulnerable app: a link
  to `/help?q=<script>…` ran script in the lab's origin (cookies are `SameSite=Lax`, so a top-level
  navigation is signed in), and a cross-site iframe of `/lab` passed the same-origin check on the
  reset button. Requests marked `Sec-Fetch-Site: cross-site` now get a 403 and every response
  carries `X-Frame-Options: DENY`. Tests: `test_other_websites_cannot_drive_the_lab`,
  `test_pages_cannot_be_framed`; also checked in Chromium from a page on `localhost:4163`.
- CI pins every action to a full commit SHA (tag in a comment) and checks out with
  `persist-credentials: false`, so later steps never see the job token.

### Changed

- Performance, accessibility and maintainability pass. Measured first: cold start to first response
  0.25 s; `/lab` 8.9 kB at 1.6 ms, `style.css` 12 kB, `lab.js` 1.5 kB, no third-party requests, one runtime
  dependency (Flask); full test suite 19 s. Nothing worth optimising, so nothing was. Unused code check:
  `ruff` (F rules) is clean and there is no unused dependency.
- axe-core 4.10 (WCAG 2.0 to 2.2 A/AA plus best practices) run in Chromium over every Quillbook and lab page,
  light and dark, at 1200 px and 320 px. Found and fixed: the lab bar was a second `banner` landmark next to
  Quillbook's header (now a labelled `nav`), and the invoice, credit and admin tables forced horizontal
  page scroll at 320 px (now each sits in a keyboard-focusable, labelled scroll region). After the fix: zero
  violations, no horizontal page scroll. Test: `test_quillbook_pages_have_one_banner_and_scrollable_tables_are_focusable`.
- `docs/demo.gif` re-recorded from the running app; it shows eleven seals and "0 of 11 flags".
- Not changed: Windows and Safari remain untested.

### Added

- Challenge 11, race condition. Alice has a single-use voucher, `QB-WELCOME-10`; the Account page
  has a voucher form and a credit history. `vulnerable/race_condition.redeem_voucher` checks "unused",
  waits half a second for the (simulated) voucher partner, then marks it used, so parallel requests
  all get the credit. The flag is captured when the same voucher appears twice in `credit_log`. The
  last hint is a console snippet (five `fetch` calls with `Promise.all`), and `e2e/solve.cjs` runs that
  hint text verbatim in Chromium. The reference fix claims the voucher with one conditional `UPDATE`
  and checks `rowcount`. The check fires four simultaneous requests from threads; it also requires
  the partner's verdict to be respected (withdrawn `QB-SPRING-25`), so deleting the slow call does not
  count as a fix. Half-fix and sound-alternative tests: an atomic claim whose rowcount is ignored must
  fail; a `threading.Lock` passes. A `.breachlab/app.db` from an older version (no `credit_log` table)
  is reseeded on start, flags kept. README screenshots retaken with eleven challenges.
- Launch material: a demo GIF (`docs/demo.gif`, recorded from the real app by `e2e/demo.cjs`), a comparison with
  Juice Shop, DVWA, WebGoat and PortSwigger's academy, `CONTRIBUTING.md` and issue templates.
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

- A request that had opened `app.db` just before a reset swapped it (the "readonly database" case noted below)
  now gets a 503 "Reload the page" notice instead of a 500. Test: `test_a_request_caught_by_a_reset_gets_a_retry_notice_not_a_500`.
- Reliability pass (found by fuzzing odd input and hammering a running server with 24 parallel
  learners):
  - `/invoices/99999999999999999999` was a 500 (`OverflowError` from SQLite's 64-bit integers); it is a 404.
  - Pressing Reset twice, or resetting while another page loads, could 500 with "no such table" or
    "table already exists", because the reset dropped and recreated tables in place. It now builds the
    new database beside the old one, swaps it in with `os.replace` and holds a lock, so a request sees
    all-old or all-new data. A request that writes through a connection opened before the swap can
    still fail once ("readonly database"); reloading fixes it.
  - `--port 70000`, `-1` and `0` (and the same for `--attacker-port`) ended in a traceback; they are
    now a usage error ("must be between 1 and 65535").
  - Files the lab reads or writes (Mallory's page, exports, wordlist, solution sources) are now
    always UTF-8 instead of the platform default, which matters on Windows. Not run on Windows; the
    UTF-8 round-trip test guards it on any platform.
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

- The race condition check sets `PARTNER_SECONDS` to 0.3 (0.5 in the real lab) and releases four
  signed-in test clients through a `threading.Barrier`. It was stable over repeated runs here; if it
  ever flakes in CI, widen the delay rather than retrying. The voucher route also goes through
  `csrf.is_request_genuine`, so the check posts each client's real token.
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
  `prompt()`, no RS256/HS256 confusion, the reference SSRF fix resolves host names, Windows is unverified.

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
