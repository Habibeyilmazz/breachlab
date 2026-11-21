"""Challenge: mass assignment in the profile update.

Stage 2: patch profile_changes, then run `pytest fix_tests -k mass_assignment`.
"""


# BREACHLAB: patch this function
def profile_changes(form: dict) -> dict:
    """Return the user columns to update, taken from the submitted account form."""
    return {field: value for field, value in form.items() if field != "csrf_token"}
