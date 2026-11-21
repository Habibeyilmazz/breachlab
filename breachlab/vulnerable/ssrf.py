"""Challenge: server-side request forgery in "Import from URL".

Stage 2: patch is_allowed_url, then run `pytest fix_tests -k ssrf`.
"""


# BREACHLAB: patch this function
def is_allowed_url(url: str) -> bool:
    """Decide whether the server may fetch `url` on a user's behalf."""
    return url.startswith(("http://", "https://"))
