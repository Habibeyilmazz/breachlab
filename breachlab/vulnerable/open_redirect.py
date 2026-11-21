"""Challenge: open redirect after login.

Stage 2: patch redirect_target, then run `pytest fix_tests -k open_redirect`.
"""


# BREACHLAB: patch this function
def redirect_target(next_url):
    """Return where to send the user after a successful login."""
    return next_url or "/invoices"
