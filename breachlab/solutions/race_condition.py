"""Reference fix: race condition in voucher redemption.

Why the hole existed
    The code asked "is this voucher unused?", then spent half a second on the
    partner call, then wrote "used". Each request runs in its own thread with
    its own database connection, so every request that arrived during that
    half second read the same answer, "unused", and every one of them credited
    the voucher. Check-then-act is only safe when nothing can happen between
    the check and the act.

Why this fix works
    The check and the claim are now one statement:
    UPDATE ... SET redeemed_by = ? WHERE code = ? AND redeemed_by IS NULL.
    SQLite runs one write at a time, so exactly one request finds the voucher
    unclaimed and changes the row (rowcount 1); every other request changes
    nothing (rowcount 0) and gets None. The credit is written in the same
    transaction as the claim, so a crash cannot leave a claimed voucher
    without its credit, or the other way round. The slow partner call happens
    before the transaction, so no lock is held while waiting on the network.

The secure pattern
    Let the database decide "first one wins": a conditional UPDATE whose
    rowcount you check, a UNIQUE constraint on the redemption, or
    SELECT ... FOR UPDATE in databases that have it. A lock in your own code
    (threading.Lock) also closes this race, but only inside one process:
    production apps run several workers on several machines. Never keep the
    result of a check in a variable and act on it later for anything that is
    limited: coupons, stock, account balances, invitations, rate limits.
"""


def redeem_voucher(db, user_id, code, partner_confirms):
    """Credit a one-time voucher to the user's account. Return the cents credited, or None."""
    if not partner_confirms(code):
        return None
    with db:
        claimed = db.execute(
            "UPDATE vouchers SET redeemed_by = ? WHERE code = ? AND redeemed_by IS NULL", (user_id, code)
        ).rowcount
        if claimed != 1:
            return None
        cents = db.execute("SELECT cents FROM vouchers WHERE code = ?", (code,)).fetchone()["cents"]
        db.execute("UPDATE users SET credit_cents = credit_cents + ? WHERE id = ?", (cents, user_id))
    return cents
