"""Reference fix: cross-site request forgery.

Why the hole existed
    Browsers attach cookies to a request based on where it is going, not on which
    page sent it. The server saw a valid session cookie and assumed the user meant
    to submit the form. SameSite=Lax cookies stop other *sites*, but not other
    origins on the same site (another port, a sibling subdomain), and not every
    browser applies the same defaults.

Why this fix works
    The form now has to prove it was rendered by us: it must carry the random
    token stored in the user's session. Another origin can make the browser send
    the cookie, but it cannot read our pages, so it cannot learn the token.
    hmac.compare_digest compares in constant time, and the empty-token check
    keeps "no token in session" from matching "no token in form".

The secure pattern
    Every state-changing request (POST, PUT, DELETE) needs an unguessable
    per-session token checked on the server; use your framework's CSRF
    protection for all forms instead of doing it by hand per route. Never change
    state on GET. Keep SameSite cookies and an Origin header check as extra
    layers. Note that any XSS on the same origin defeats CSRF tokens, because the
    script can read them.
"""

import hmac


def is_request_genuine(session_token: str, submitted_token: str) -> bool:
    """Decide whether a form post really came from our own page."""
    return bool(session_token) and hmac.compare_digest(session_token.encode(), submitted_token.encode())
