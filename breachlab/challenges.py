"""The twelve challenges: story, goal, hints and where the vulnerable code lives.

Story, goal and hint strings are trusted HTML written here, never user input.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Challenge:
    id: str  # also the module name in breachlab/vulnerable and breachlab/solutions
    title: str
    weakness: str  # the general bug class, in plain words
    start: str  # page of the fake app where the attack begins
    function: str  # the function the learner patches in stage 2
    flag: str
    story: str
    goal: str
    hints: tuple[str, str, str]


# {"alg":"none"} . {"sub":"alice","role":"admin"} . no signature: the answer to the JWT challenge
UNSIGNED_ADMIN_TOKEN = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiJ9."

# Paste into the developer console on /account: five redemptions at once. redirect: "manual" keeps the
# flag banner for the next page you open instead of spending it on the redirected fetch.
RACE_SNIPPET = (
    "const f = document.getElementById('voucher'); f.code.value = 'QB-WELCOME-10';"
    " await Promise.all([1, 2, 3, 4, 5].map(() =>"
    " fetch(f.action, {method: 'POST', body: new FormData(f), redirect: 'manual'}))); location.reload();"
)

CHALLENGES = [
    Challenge(
        id="sqli",
        title="SQL injection",
        weakness="User input pasted into a SQL string",
        start="/invoices",
        function="search_invoices",
        flag="BL{quote-unquote-everything}",
        story=(
            "<p>Quillbook's invoice search only shows <em>your</em> invoices. Bob keeps bragging about a huge"
            " deal with a shipping company, and the search box is right there.</p>"
            "<p>Try searching for a customer with an apostrophe in the name. The page does not fail gracefully.</p>"
        ),
        goal="Make the invoice search return a row that is not one of your own invoices.",
        hints=(
            "Search for <code>O'Brien</code>. The database error tells you your text lands inside a quoted SQL"
            " string. What if your text closed that quote itself?",
            "The query looks like <code>… WHERE owner_id = 1 AND customer LIKE '%<em>your text</em>%' …</code>."
            " A quote ends the string; <code>--</code> turns the rest of the line into a comment.",
            "Search for <code>' OR 1=1--</code> to list everyone's invoices. For a bigger prize, read another"
            " table: <code>' UNION SELECT id, username, 0, password_hash FROM users--</code>",
        ),
    ),
    Challenge(
        id="reflected_xss",
        title="Reflected XSS",
        weakness="A URL parameter echoed into the page as HTML",
        start="/help",
        function="results_heading",
        flag="BL{mirror-mirror-on-the-page}",
        story=(
            "<p>The help centre repeats your search term back to you in bold. Whatever is in the"
            " <code>q</code> parameter of the link ends up in the page, so a link you send to a colleague"
            " can carry more than a question.</p>"
        ),
        goal="Craft a <code>/help?q=…</code> link that runs JavaScript when opened. Call <code>alert()</code> to prove it.",
        hints=(
            "Search the help for <code>&lt;u&gt;hello&lt;/u&gt;</code>. Is the result underlined, or do you see the tags?",
            "If the browser renders your tags, it will also run a script tag you put there.",
            "Open <code>/help?q=&lt;script&gt;alert(1)&lt;/script&gt;</code>. If your browser blocks that,"
            " try <code>&lt;img src=x onerror=alert(1)&gt;</code>.",
        ),
    ),
    Challenge(
        id="stored_xss",
        title="Stored XSS",
        weakness="Saved user content rendered as HTML for everyone",
        start="/notes",
        function="render_note",
        flag="BL{sticky-note-sticky-fingers}",
        story=(
            "<p>The team board shows every note to every colleague, with line breaks kept just as you typed"
            " them. Carol reads the board every morning while logged in as the administrator.</p>"
            "<p>A note that carries a script would run in her browser, with her session.</p>"
        ),
        goal="Post a note that runs JavaScript for anyone who opens the board. Call <code>alert()</code> to prove it.",
        hints=(
            "Post a note containing <code>&lt;b&gt;bold?&lt;/b&gt;</code> and look at how it is displayed.",
            "The board keeps your HTML. Unlike the reflected case, the payload now lives in the database"
            " and fires for every visitor, no special link needed.",
            "Post <code>&lt;script&gt;alert(document.domain)&lt;/script&gt;</code> as a note. It runs as soon"
            " as the board comes back, and again for every visitor. Had enough of the pop-up? Reset the app data"
            " on the challenge list.",
        ),
    ),
    Challenge(
        id="idor",
        title="Insecure direct object reference",
        weakness="A record fetched by id without checking who owns it",
        start="/invoices",
        function="load_invoice",
        flag="BL{thats-not-your-invoice}",
        story=(
            "<p>Open one of your invoices and look at the address bar: <code>/invoices/1001</code>."
            " The list page only links to your own invoices, but a link is not a lock.</p>"
            "<p>Bob's invoice numbers start at 2001.</p>"
        ),
        goal="Read the confidential memo on an invoice that belongs to Bob.",
        hints=(
            "The number at the end of the invoice address is the invoice's id in the database.",
            "Nothing stops you from typing a different number. Yours are 1001 to 1003.",
            "Open <code>/invoices/2001</code>.",
        ),
    ),
    Challenge(
        id="path_traversal",
        title="Path traversal",
        weakness="A file name from the request joined onto a folder path",
        start="/invoices/1001",
        function="export_path",
        flag="BL{dot-dot-slash-payroll}",
        story=(
            "<p>Each of your invoices has a &ldquo;Download text export&rdquo; link:"
            " <code>/exports/download?file=invoice-1001.txt</code>. The server reads that file from its"
            " <code>exports</code> folder. Carol's note on the team board says payroll lives"
            " &ldquo;next door&rdquo;.</p>"
        ),
        goal="Download a file from outside the exports folder.",
        hints=(
            "The <code>file</code> parameter is a file name. What does <code>..</code> mean in a file path?",
            "<code>../</code> climbs one folder up. From <code>exports</code>, the neighbour folder is"
            " <code>../private/</code>.",
            "Open <code>/exports/download?file=../private/payroll-2026.txt</code>. The lab fences traversal"
            " into its own data folder, so your real files stay unread; a real server has no such fence.",
        ),
    ),
    Challenge(
        id="open_redirect",
        title="Open redirect",
        weakness="Redirecting to an address taken from the URL",
        start="/login",
        function="redirect_target",
        flag="BL{trust-me-click-here}",
        story=(
            "<p>When your session expires, Quillbook sends you to <code>/login?next=/invoices</code> and"
            " returns you to where you were after you sign in. The link starts with the real Quillbook"
            " address, which is exactly what makes it useful to a phisher.</p>"
        ),
        goal="Build a login link that, after a successful sign-in, sends the user to another website.",
        hints=(
            "Sign out and look at the login address. What decides where you land after signing in?",
            "The <code>next</code> value is used as the redirect target without any checks. It does not have to be a path.",
            "Sign out, open <code>/login?next=https://example.com/</code> and sign in as alice."
            " Come back to the lab afterwards to see the flag.",
        ),
    ),
    Challenge(
        id="mass_assignment",
        title="Mass assignment",
        weakness="Saving every submitted field, not just the ones on the form",
        start="/account",
        function="profile_changes",
        flag="BL{one-field-too-many}",
        story=(
            "<p>The account page lets you change your display name and email. The server takes the submitted"
            " form and writes each field to your user record. Your record has more columns than the form has"
            " inputs: <code>role</code> and <code>credit_cents</code>, for instance.</p>"
        ),
        goal="Change a field of your own user record that the form does not offer, such as your role.",
        hints=(
            "The form sends <code>display_name</code> and <code>email</code>. Who says a request can only contain those?",
            "Use the browser's developer tools to add an input to the form before saving, or replay the request with curl.",
            'Add <code>&lt;input name="role" value="admin"&gt;</code> inside the account form, save, then visit'
            " <code>/admin</code>.",
        ),
    ),
    Challenge(
        id="csrf",
        title="Cross-site request forgery",
        weakness="A state-changing request accepted without proof it came from the app's own page",
        start="/account",
        function="is_request_genuine",
        flag="BL{it-wasnt-me-it-was-my-browser}",
        story=(
            "<p>Changing your email is a plain form post, and your browser attaches the session cookie to any"
            " request for this address. The cookie is <code>SameSite=Lax</code>, which stops other"
            " <em>sites</em>, but a page on a different port of the same host is the same site.</p>"
            "<p>The form does contain a hidden token. Nobody checks it.</p>"
        ),
        goal="While signed in, have a page served from a different origin change your Quillbook email.",
        hints=(
            "Write an HTML page with a form whose <code>action</code> is this app's <code>/account</code> URL and"
            " whose fields are <code>display_name</code> and <code>email</code>.",
            "The page has to come from another origin. Write it in the <em>Mallory's site</em> box below, save,"
            " and open Mallory's site in the browser where you are signed in. It runs on the next port of this"
            " host: a different origin, but the same site, so the <code>SameSite=Lax</code> cookie still goes along.",
            "Make it fire by itself. The whole attacker page, to paste into Mallory's site:"
            " <code>&lt;form method=&quot;post&quot; action=&quot;ORIGIN/account&quot;&gt;&lt;input"
            " name=&quot;display_name&quot; value=&quot;Alice&quot;&gt;&lt;input name=&quot;email&quot;"
            " value=&quot;mallory@evil.test&quot;&gt;&lt;/form&gt;"
            "&lt;script&gt;document.forms[0].submit()&lt;/script&gt;</code>"
            " The lab captures the flag when the email changes through a request whose"
            " <code>Origin</code> header is not this app.",
        ),
    ),
    Challenge(
        id="weak_jwt",
        title="Forged JWT",
        weakness="Tokens verified with a guessable secret and an algorithm chosen by the token",
        start="/account",
        function="verify",
        flag="BL{none-of-your-algorithm}",
        story=(
            "<p>The account page shows your API token, a JWT. <code>GET /api/me</code> accepts it as"
            " <code>Authorization: Bearer &lt;token&gt;</code>, and <code>GET /api/admin/report</code> wants one"
            " whose <code>role</code> is <code>admin</code>.</p>"
            "<p>A JWT is three base64url parts: header, claims, signature. The first two are not secret.</p>"
        ),
        goal="Call <code>/api/admin/report</code> successfully with a token you made yourself.",
        hints=(
            "Decode the first two parts of your token (base64url). The header names the signing algorithm;"
            " the claims say who you are.",
            "Two ways in. The verifier believes the header, so try <code>{&quot;alg&quot;:&quot;none&quot;}</code>"
            " with an empty signature. Or the HS256 secret is a common word: the repository ships"
            " <code>breachlab/wordlists/jwt-secrets.txt</code>.",
            "Unsigned token: base64url of <code>{&quot;alg&quot;:&quot;none&quot;}</code>, a dot, base64url of"
            " <code>{&quot;sub&quot;:&quot;alice&quot;,&quot;role&quot;:&quot;admin&quot;}</code>, and a trailing dot,"
            f" which makes <code>{UNSIGNED_ADMIN_TOKEN}</code>"
            f" Send it with <code>curl -H 'Authorization: Bearer {UNSIGNED_ADMIN_TOKEN}'"
            " ORIGIN/api/admin/report</code>",
        ),
    ),
    Challenge(
        id="ssrf",
        title="Server-side request forgery",
        weakness="The server fetching whatever URL it is given",
        start="/invoices/import",
        function="is_allowed_url",
        flag="BL{the-call-is-coming-from-inside}",
        story=(
            "<p>&ldquo;Import from URL&rdquo; makes the Quillbook server download a supplier's invoice and show"
            " you a preview. Bob's note on the team board mentions an internal address that only answers the app"
            " server. Open <code>/internal/keys</code> in your browser: you are turned away.</p>"
            "<p>You cannot reach it. The server can, and it fetches what you ask for.</p>"
        ),
        goal="Read the billing keys from <code>/internal/keys</code>.",
        hints=(
            "The import feature takes a full URL. Which machine makes the request for that URL?",
            "From the server's point of view, &ldquo;itself&rdquo; is <code>127.0.0.1</code> on the port you see"
            " in your address bar.",
            "Import <code>ORIGIN/internal/keys</code>. The lab never opens"
            " outbound connections: only requests to itself are really performed.",
        ),
    ),
    Challenge(
        id="race_condition",
        title="Race condition",
        weakness="A limit checked in one step and enforced in a later one",
        start="/account",
        function="redeem_voucher",
        flag="BL{two-requests-one-voucher}",
        story=(
            "<p>Quillbook sent Alice a welcome voucher, <code>QB-WELCOME-10</code>, worth $10 of account credit."
            " Each voucher works once. Before crediting it, Quillbook asks its voucher partner whether the code"
            " is genuine, and the partner takes about half a second to answer.</p>"
            "<p>The server handles requests in parallel. It checks whether the voucher is unused before that"
            " half second and marks it used after.</p>"
        ),
        goal="Get the same single-use voucher credited to your account more than once.",
        hints=(
            "Redeem <code>QB-WELCOME-10</code> on the Account page and notice the pause. Then try it again."
            " Already used it? Reset the app data on the challenge list to get it back.",
            "A second request that arrives during the pause still sees an unused voucher. Two tabs and fast"
            " clicks rarely land inside half a second; sending several requests from code does.",
            "Reset the app data, open the Account page, open the browser's developer console and run:"
            f" <code>{RACE_SNIPPET}</code> The credit history then shows the voucher more than once.",
        ),
    ),
    Challenge(
        id="command_injection",
        title="Command injection",
        weakness="User input pasted into a shell command line",
        start="/help/mail-check",
        function="ping_command",
        flag="BL{semicolon-and-a-whole-new-command}",
        story=(
            "<p>Support kept getting &ldquo;my invoice emails never arrive&rdquo;, so a developer added a mail server"
            " check to the help centre: you type your mail server's name and Quillbook pings it from its own servers.</p>"
            "<p>The quickest way to run ping from Python is to build the command line as text and hand it to the"
            " shell. Your text goes in the middle of that line.</p>"
        ),
        goal="Make the server's shell run a command of your choosing, not only ping.",
        hints=(
            "Ping <code>127.0.0.1</code> and read the reply: it is what ping prints. The server runs"
            " <code>ping -c 1 <em>your text</em></code> through <code>/bin/sh</code>.",
            "To a shell, <code>;</code>, <code>&amp;&amp;</code>, <code>|</code> and a new line each start another"
            " command, and <code>$(&hellip;)</code> runs one and pastes in its output.",
            "Enter <code>127.0.0.1; id</code> in the mail server check. BreachLab never really runs it: the lab reads"
            " the command line and tells you what a real server would have run.",
        ),
    ),
]

BY_ID = {c.id: c for c in CHALLENGES}
FLAGS = {c.id: c.flag for c in CHALLENGES}
