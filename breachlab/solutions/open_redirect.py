"""Reference fix: open redirect.

Why the hole existed
    The login page redirected to whatever `next` contained. A link that starts
    with the real site's address but ends up on an attacker's page is ideal for
    phishing: the victim checks the domain, signs in for real, and lands on a fake
    "session expired, sign in again" page.

Why this fix works
    Only local paths are accepted: the target must start with exactly one "/".
    That rules out absolute URLs (https://evil.example), scheme-relative URLs
    (//evil.example) and the backslash variants browsers treat the same way
    (/\\evil.example). Control characters are rejected because browsers strip
    them before interpreting a URL. Anything else falls back to a fixed page.

The secure pattern
    Do not redirect to user-supplied URLs. Prefer a server-side value (remember
    the page in the session) or a fixed list of destinations. If a path must come
    from the request, allow local paths only and validate them the way a browser
    reads them, not the way a URL parser on the server does.
"""


def redirect_target(next_url):
    """Return where to send the user after a successful login."""
    is_local_path = (
        next_url.startswith("/")
        and not next_url.startswith(("//", "/\\"))
        and "\\" not in next_url
        and all(ch > " " and ch != "\x7f" for ch in next_url)
    )
    return next_url if is_local_path else "/invoices"
