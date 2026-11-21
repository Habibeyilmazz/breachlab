"""Reference fix: mass assignment.

Why the hole existed
    The handler copied every submitted field onto the user record. The HTML form
    only had two inputs, but the form is a suggestion: a request can carry any
    field name, including `role` and `credit_cents`.

Why this fix works
    The function now builds the update from a fixed list of fields the user is
    allowed to change. Extra fields in the request are simply never looked at.

The secure pattern
    Allowlist, never blocklist: name the fields each endpoint may write. A
    blocklist ("everything except role") silently becomes wrong the day someone
    adds a new sensitive column. The same applies to ORMs and JSON APIs that can
    bind a whole request body to a model: bind to a small input type that has
    only the editable fields. Privileged fields get their own, separately
    authorized, endpoint.
"""

EDITABLE_FIELDS = ("display_name", "email")


def profile_changes(form: dict) -> dict:
    """Return the user columns to update, taken from the submitted account form."""
    return {field: form[field] for field in EDITABLE_FIELDS if field in form}
