"""Reference fix: insecure direct object reference.

Why the hole existed
    The page looked an invoice up by id and showed it. Being signed in was checked;
    being *allowed to see this particular invoice* was not. Ids are easy to guess,
    and hiding the links is not access control.

Why this fix works
    Ownership is part of the query itself: a row is only returned when its id AND
    its owner match the signed-in user. Someone else's invoice now looks exactly
    like one that does not exist (404), which also avoids confirming which ids are real.

The secure pattern
    Check authorization for every object on every request, on the server, as close
    to the data access as possible. Scope queries by the current user or tenant
    instead of fetching first and checking later. Random ids (UUIDs) make guessing
    harder but do not replace the check.
"""


def load_invoice(db, user_id, invoice_id):
    """Return the invoice row the signed-in user asked for, or None."""
    return db.execute("SELECT * FROM invoices WHERE id = ? AND owner_id = ?", (invoice_id, user_id)).fetchone()
