"""Challenge: reflected XSS in the help search.

Stage 2: patch results_heading, then run `pytest fix_tests -k reflected_xss`.
"""

from markupsafe import Markup


# BREACHLAB: patch this function
def results_heading(query, count):
    """Return the HTML heading shown above help search results."""
    return Markup(f"{count} result(s) for <strong>{query}</strong>")
