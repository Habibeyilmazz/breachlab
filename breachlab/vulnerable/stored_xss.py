"""Challenge: stored XSS on the team board.

Stage 2: patch render_note, then run `pytest fix_tests -k stored_xss`.
"""

from markupsafe import Markup


# BREACHLAB: patch this function
def render_note(body):
    """Return a note's body as HTML, keeping the author's line breaks."""
    return Markup(body.replace("\n", "<br>"))
