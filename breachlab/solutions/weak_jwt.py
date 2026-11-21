"""Reference fix: forged JWT.

Why the hole existed
    Two independent mistakes. First, the verifier read the algorithm from the
    token's own header, and that header is written by whoever made the token. A
    token saying "alg: none" was accepted with no signature at all. Second, the
    HS256 secret was a dictionary word, so anyone holding one valid token could
    try a wordlist offline until the signature matched, then sign anything.

Why this fix works
    The algorithm is decided by the server: only HS256 is accepted, whatever the
    header claims. The secret is 32 random bytes, far beyond guessing. Signatures
    are compared with hmac.compare_digest so response timing does not leak how
    many characters matched. The claims are only parsed after the signature has
    been verified, so unauthenticated input never reaches the JSON parser.

The secure pattern
    Use a maintained JWT library and always pass the list of algorithms you
    accept; never let the token choose. The same idea prevents the RS256/HS256
    "key confusion" attack, where a public RSA key is abused as an HMAC secret.
    Generate secrets with a CSPRNG and load them from a secret store. (Here the
    secret is made at startup, so tokens stop working when the server restarts;
    a real service would persist and rotate it.) Give tokens a short expiry
    (`exp`) and check it.
"""

import base64
import hashlib
import hmac
import json
import secrets

SECRET = secrets.token_bytes(32)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _signature(signing_input: str) -> str:
    return _b64(hmac.new(SECRET, signing_input.encode(), hashlib.sha256).digest())


def issue(claims: dict) -> str:
    """Return a signed token carrying `claims`."""
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps(claims).encode())
    return f"{header}.{payload}.{_signature(f'{header}.{payload}')}"


def verify(token: str):
    """Return the token's claims when the token is valid, otherwise None."""
    try:
        header_b64, payload_b64, signature = token.split(".")
        header = json.loads(_unb64(header_b64))
        if not isinstance(header, dict) or header.get("alg") != "HS256":
            return None
        expected = _signature(f"{header_b64}.{payload_b64}")
        if not hmac.compare_digest(signature.encode(), expected.encode()):
            return None
        claims = json.loads(_unb64(payload_b64))  # parsed only once the signature has been checked
    except (ValueError, RecursionError):  # not base64, not JSON, or absurdly nested JSON
        return None
    return claims if isinstance(claims, dict) else None
