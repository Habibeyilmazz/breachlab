"""Challenge: SQL injection in the invoice search.

Stage 2: patch search_invoices, then run `pytest fix_tests -k sqli`.
"""


# BREACHLAB: patch this function
def search_invoices(db, user_id, query):
    """Return (id, customer, amount_cents, status) rows of the user's invoices whose customer contains `query`."""
    sql = (
        "SELECT id, customer, amount_cents, status FROM invoices "
        f"WHERE owner_id = {user_id} AND customer LIKE '%{query}%' ORDER BY id"
    )
    return db.execute(sql).fetchall()
