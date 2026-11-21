"""Reference fix: SQL injection.

Why the hole existed
    The search text was pasted into the SQL string, so the database could not tell
    where the programmer's query ended and the user's data began. A quote in the
    input closed the string literal and everything after it ran as SQL.

Why this fix works
    The query text is now a constant. The values travel separately as bound
    parameters (the `?` placeholders), and the database never parses them as SQL.
    No input, however strange, can change the shape of the query.

The secure pattern
    Always use parameterized queries (or an ORM/query builder that does). Never
    build SQL with f-strings, `+` or `%`. Escaping quotes by hand is fragile: the
    rules differ between databases and contexts, and one missed case (a second
    quote, a number that is not quoted at all) reopens the hole.
    Things a placeholder cannot stand for (table or column names, sort direction)
    must be picked from a fixed list in your code, never copied from the request.
"""


def search_invoices(db, user_id, query):
    """Return (id, customer, amount_cents, status) rows of the user's invoices whose customer contains `query`."""
    return db.execute(
        "SELECT id, customer, amount_cents, status FROM invoices "
        "WHERE owner_id = ? AND customer LIKE '%' || ? || '%' ORDER BY id",
        (user_id, query),
    ).fetchall()
