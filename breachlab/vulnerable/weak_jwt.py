"""Challenge: forged JWT for the API.

Stage 2: patch this module (the secret and verify), then run `pytest fix_tests -k weak_jwt`.
"""

import base64
import hashlib
import hmac
import json

SECRET = b"sunshine"


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


# BREACHLAB: patch this function (and the secret above)
def verify(token: str):
    """Return the token's claims when the token is valid, otherwise None."""
    try:
        header_b64, payload_b64, signature = token.split(".")
        header = json.loads(_unb64(header_b64))
        claims = json.loads(_unb64(payload_b64))
    except (ValueError, RecursionError):
        return None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return None
    algorithm = str(header.get("alg", "")).lower()
    if algorithm == "none":
        return claims  # unsigned tokens were handy for the mobile team's test builds
    if algorithm == "hs256" and signature == _signature(f"{header_b64}.{payload_b64}"):
        return claims
    return None
