"""Challenge: race condition in voucher redemption.

Stage 2: patch redeem_voucher, then run `pytest fix_tests -k race_condition`.
"""


# BREACHLAB: patch this function
def redeem_voucher(db, user_id, code, partner_confirms):
    """Credit a one-time voucher to the user's account. Return the cents credited, or None.

    partner_confirms(code) asks Quillbook's voucher partner whether the code is still
    genuine. It is a network call to another company and takes about half a second.
    """
    voucher = db.execute("SELECT cents, redeemed_by FROM vouchers WHERE code = ?", (code,)).fetchone()
    if voucher is None or voucher["redeemed_by"] is not None:
        return None
    if not partner_confirms(code):
        return None
    with db:
        db.execute("UPDATE vouchers SET redeemed_by = ? WHERE code = ?", (user_id, code))
        db.execute("UPDATE users SET credit_cents = credit_cents + ? WHERE id = ?", (voucher["cents"], user_id))
    return voucher["cents"]
