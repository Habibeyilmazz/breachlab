"""Challenge: cross-site request forgery on the account form.

Stage 2: patch is_request_genuine, then run `pytest fix_tests -k csrf`.
"""


# BREACHLAB: patch this function
def is_request_genuine(session_token: str, submitted_token: str) -> bool:
    """Decide whether a form post really came from our own page.

    session_token is the random value stored in the user's session at login; the account
    form embeds it in a hidden field, which arrives here as submitted_token.
    """
    return True
