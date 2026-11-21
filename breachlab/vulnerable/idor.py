"""Challenge: insecure direct object reference on the invoice page.

Stage 2: patch load_invoice, then run `pytest fix_tests -k idor`.
"""


# BREACHLAB: patch this function
def load_invoice(db, user_id, invoice_id):
    """Return the invoice row the signed-in user asked for, or None."""
    return db.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
