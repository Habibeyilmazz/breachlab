# BreachLab

Learn web security by breaking a small, realistic app and then fixing it, entirely on your own machine.
Twelve guided challenges, each with a story, three hints, automatic flag detection, and a test that only passes once you have closed the hole.

> [!CAUTION]
> **BreachLab is vulnerable on purpose. Never deploy it, never expose it to a network.**
> It binds to `127.0.0.1` only, refuses any other bind address, and rejects requests that do not come
> from and for your own machine. Keep it that way: do not put it behind a proxy, a tunnel or a container port mapping.

![Recording of the lab: the SQL injection challenge, then a search for ' OR 1=1-- in Quillbook shows other people's invoices and captures the flag](docs/demo.gif)

The recording is the real app, driven by `e2e/demo.cjs`. Below: the challenge list with all twelve flags captured and four holes fixed.

![The challenge list with all twelve flags captured and four holes fixed](docs/screenshots/progress.png)

## Quickstart

You need Python 3.10 or newer and git. The only runtime dependency is Flask.

```bash
git clone https://github.com/Habibeyilmazz/breachlab.git
cd breachlab
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m breachlab
```

Open <http://127.0.0.1:4160/> and pick a challenge. Sign in to the practice app as `alice` / `alice-demo`.
The lab also uses the next port, 4161, for Mallory's site (see below); `--port` and `--attacker-port` change both.

Developed and tested on macOS and Linux. Windows is untested.

## How a challenge goes

**1. Break it.** Each challenge page tells a short story about Quillbook, the fake notes-and-invoices
app, and states a goal. Attack the app in your browser (or with curl). Three hints are there if you get
stuck; the third one is the answer. When the attack works, the lab notices by itself and shows your flag.

![Quillbook's invoice search after an SQL injection, with the "Flag captured" banner](docs/screenshots/exploit.png)

**2. Fix it.** The hole is always in one small function under `breachlab/vulnerable/`. Open the file
named on the challenge page, patch the function, and run the provided test in a second terminal
(the server keeps running in the first; activate the virtual environment there too):

```bash
source .venv/bin/activate
pytest fix_tests -k sqli
```

The test replays the attack (with a few variations) and also checks that the feature still works, so
deleting the feature does not count as a fix. The "Check my fix" button on the challenge page runs the
same check. The server restarts by itself when you save a file.

![A challenge page: story, goal, hints, and the fix stage reporting "Fixed"](docs/screenshots/fix.png)

Stuck on the fix? Every challenge has a reference fix in `breachlab/solutions/`, with an explanation of
why the hole existed, why the fix works, and the general pattern to use in real code. The challenge
page can show it (behind a spoiler), and `python -m breachlab --fixed` runs the whole app on the
reference fixes so you can watch your attacks fail.

**3. Start over, if you like.** The "Start over" button at the bottom of each challenge page puts the
original vulnerable function back (`git checkout HEAD -- breachlab/vulnerable/<challenge>.py`, so your
changes to that file are lost), restores the sample data and clears that challenge's flag and fix result.
Use it to break a challenge again, or to throw away a patch that went wrong. It needs the git checkout from
the quickstart; without git it still clears the progress and tells you to undo the file by hand. If you
committed your patch, HEAD is your patch, and there is nothing to put back.

## The twelve challenges

| # | Challenge | Where in Quillbook | Function you patch |
|---|-----------|--------------------|--------------------|
| 1 | SQL injection | Invoice search | `sqli.search_invoices` |
| 2 | Reflected XSS | Help centre search | `reflected_xss.results_heading` |
| 3 | Stored XSS | Team board | `stored_xss.render_note` |
| 4 | Insecure direct object reference | Invoice page | `idor.load_invoice` |
| 5 | Path traversal | Invoice export download | `path_traversal.export_path` |
| 6 | Open redirect | Login `next` parameter | `open_redirect.redirect_target` |
| 7 | Mass assignment | Account profile form | `mass_assignment.profile_changes` |
| 8 | Cross-site request forgery | Account profile form | `csrf.is_request_genuine` |
| 9 | Forged JWT (`alg: none` and a weak secret) | API token | `weak_jwt.verify` |
| 10 | Server-side request forgery | Import invoice from URL | `ssrf.is_allowed_url` |
| 11 | Race condition | Voucher redemption on the account page | `race_condition.redeem_voucher` |
| 12 | Command injection | Mail server check in the help centre | `command_injection.ping_command` |

## Features

- Twelve challenges with a story, a goal, three progressive hints and a flag each.
- Automatic detection: the server recognises a successful attack (a foreign row in search results, a
  read outside the exports folder, a forged admin token, a shell command line that would run more than ping, script calling `alert()`, and so on). There
  is no flag form to paste into.
- A fix stage per challenge: a marked function, a provided test, a "Check my fix" button, and a
  reference fix that explains itself.
- Mallory's site, a built-in attacker website for the CSRF challenge: write the attacker page in a box
  on the challenge page, save, and open it. It is served on the next port (4161 by default), so it is a
  different origin from the lab but the same site, which is what the attack needs. Nothing else to install
  or start. If that port is busy, the lab starts anyway and the challenge page explains how to serve the
  page with `python3 -m http.server` instead.
- A progress page showing which holes you have broken and which you have fixed, also visible as a
  strip of squares, one per challenge, in the bar above every page.
- Reset buttons: restore the sample data (keeps your flags), or wipe data and progress.
- "Start over" per challenge: original vulnerable code back from git, sample data restored, that challenge's progress cleared.
- `--fixed` mode to run the app on the reference fixes.
- Light and dark themes that follow your system setting, a phone-width layout, and keyboard focus you can see.

![The challenge list in the dark theme](docs/screenshots/progress-dark.png)

<img src="docs/screenshots/phone.png" width="300" alt="A challenge page at phone width: the bar with twelve squares sits under the BreachLab name, the command injection story and goal below">

## How it works

```
breachlab/
  app.py           Quillbook (the fake app) and the lab pages, one Flask app
  attacker.py      Mallory's site: serves the learner's CSRF attacker page on the next port
  vulnerable/      twelve small modules, one deliberately vulnerable function each  <- you edit these
  solutions/       the same twelve functions, fixed, with the explanation in the docstring
  checks.py        per challenge: replay the attack, then check the feature still works
  challenges.py    stories, goals, hints
  store.py         throwaway SQLite data and progress
fix_tests/         the provided tests (red until you fix the hole)
tests/             the lab's own test suite
e2e/solve.cjs      solves every challenge in a real browser (Playwright)
```

`app.py` never contains a hole itself. Each route calls into one function from `vulnerable/` (or
`solutions/` with `--fixed`), which is what makes a challenge patchable in one place and testable in
both states.

Data is throwaway: two small SQLite files and a few text files in `.breachlab/` inside the checkout,
created on first start. Delete the folder or use the reset buttons at any time. After a `git pull` that
brings new challenge data (the race condition challenge did), the next start restores the sample data
by itself; your flags are kept.

### Safety rails

These are part of the lab, not part of any challenge:

- **Loopback only.** `--host` accepts `127.0.0.1`, `localhost` and `::1`; anything else, such as
  `python -m breachlab --host 0.0.0.0`, exits with an error. Independently of how the
  server was started, every request is refused unless the client address is loopback and the `Host`
  header is `127.0.0.1`, `localhost` or `[::1]`. The Host check also blocks DNS rebinding from a
  hostile website open in the same browser.
- **Other websites cannot drive it.** A request the browser marks `Sec-Fetch-Site: cross-site` (a
  link on some website to the reflected XSS, a page framing the reset button) gets a 403, and no page
  can be framed (`X-Frame-Options: DENY`). Type the lab's address yourself; a link clicked on another
  site, this README on GitHub included, is refused too. The CSRF challenge's attacker page on another
  port of the same host is same-site, so it still works. Browsers without `Sec-Fetch-Site` (Safari
  before 16.4) only get the framing guard.
- **No outbound connections.** The SSRF challenge is real from the learner's side, but the "fetch" is
  sandboxed: a URL that points back at the lab is dispatched in-process, and anything else gets a
  notice instead of a request. The lab cannot be used to reach your network. One caveat: a correct
  SSRF fix has to resolve the host name it is given, so with the reference fix (or your own) a DNS
  lookup for the name you typed can leave your machine. No HTTP request ever does.
- **No commands run.** The command injection challenge never starts a process. The lab reads the command
  your code returns the way `/bin/sh` would, says what a real server would have run, and answers a plain
  ping with an invented reply. No packet is sent either.
- **Fenced file access.** The path traversal hole can leave the `exports` folder, but the lab only
  ever serves files from its own `.breachlab/files/` folder. An attempt to read `/etc/passwd` still
  captures the flag, and gets an explanation instead of the file.
- **Lab actions are same-origin.** Reset, "Check my fix", saving Mallory's page and the XSS beacon reject
  posts from other origins.
- **Mallory's site gets the same rails.** It binds to the lab's loopback address, answers only local
  clients with a loopback `Host`, refuses cross-site requests, and serves only the one page you saved
  (`.breachlab/attacker.html`, at most 20,000 characters). "Reset data and progress" deletes it.
- **No debugger.** The server always runs with Flask's debug mode off, even when `FLASK_DEBUG=1` is set
  in your shell. Werkzeug's debugger console runs Python and would sit in front of every rail above.

Same-site means any page served from `127.0.0.1` or `localhost` on another port counts, not only
Mallory's. Another local dev server you run alongside BreachLab could drive its holes, so do not browse
untrusted local pages while the lab is up.

The rails limit what a mistake can cost; they do not make the app safe. Stop the server when you are not practising.

## Tests

```bash
pytest                                   # the lab's own suite, green on a clean checkout
BREACHLAB_IMPL=solutions pytest fix_tests  # the provided tests against the reference fixes
```

The suite proves, for each of the twelve challenges, that the attack succeeds and the flag is captured
on the vulnerable code, that the reference fix blocks the attack while the feature keeps working, and
that fixing one challenge alone turns its test green. The checks are tested too: a set of plausible
half-fixes (escaping only the first quote, stripping only `<script>` tags, refusing only loopback
addresses, and so on) must fail them, and sound alternative fixes must pass. The suite also covers the
safety rails above.

Script execution for the two XSS challenges cannot be observed without a browser, so pytest proves
them by the payload arriving unescaped in the HTML. `e2e/solve.cjs` covers the rest of the way: it
drives Chromium through all twelve exploits against a running server and, with `MODE=fixed`, checks that
they all fail on the reference fixes. CI runs both.

```bash
cd e2e && npm install && npx playwright install chromium && cd ..
python -m breachlab --no-reload &
node e2e/solve.cjs          # wipes lab progress first; uses Mallory's site on port 4161
```

## Compared with the alternatives

BreachLab is small and Python-only on purpose. Other tools are better at things it does not try to do:

| | Good at | Pick it over BreachLab when |
|---|---|---|
| [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) | A huge, modern single-page app with 100+ challenges and a scoreboard | You want breadth, CTF events, or a Node/Angular target |
| [DVWA](https://github.com/digininja/DVWA) | The classic PHP target with low/medium/high difficulty levels | You want to practise the same bug at several difficulty levels in PHP |
| [WebGoat](https://github.com/WebGoat/WebGoat) | Guided lessons on Java with explanations | You are learning Java or Spring |
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Free, in-depth, browser-hosted labs and write-ups | You want depth on a topic, or labs that need no local setup |

BreachLab's niche: a Python codebase you can read in an afternoon, nothing to install but Flask, and a
fix stage that runs a test against the code you patched, so you practise defending as well as attacking.
It has twelve challenges, not hundreds, and it is not a replacement for any of the above.

## Known limits

- XSS flags are detected when your payload calls `alert()`, `confirm()` or `prompt()`. Script that
  runs without calling one of them is a working exploit the lab will not notice.
- The fix checks replay a fixed list of attack variations. Passing them means the known attacks fail,
  not that the code is proven secure.
- The JWT challenge covers `alg: none` and a guessable HS256 secret. RS256/HS256 key confusion is
  explained in the reference fix but not playable (it needs RSA, and the lab has no crypto dependency).
- On the open redirect challenge, backslash tricks such as `/\evil.example` do not work as attacks
  here because Werkzeug percent-encodes them. The fix test still requires your code to reject them.
- The race condition check sends four simultaneous redemptions and makes every `SELECT` your function
  runs through `db.execute` take an extra 50 ms, so a patch that only narrows the gap (checking again just
  before the write) still loses. A read through `db.cursor()` skips that delay. A `threading.Lock` around
  the function passes; it closes the race in this one-process lab but not in an app with several workers,
  which the reference fix explains.
- The command injection sandbox reads a command line like `/bin/sh` does for the cases that matter here
  (`;`, `&`, `|`, newlines, `$(...)`, backticks, `<`, `>`, quotes, backslashes and `#` comments). It is not a
  full shell: variable expansion such as `$HOME` and globbing are not counted as an attack, and only ping
  gets a simulated reply.
- One learner per checkout: progress is global, not per user.

## Roadmap

- A playable RS256/HS256 key confusion challenge.
- More bug classes: XXE, insecure deserialization, clickjacking.
- A defence-in-depth stage per challenge (Content-Security-Policy, cookie flags, framework CSRF protection).
- Verified Windows support.

## Contributing

Bug reports, new challenges and fixes are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT, see [LICENSE](LICENSE).
