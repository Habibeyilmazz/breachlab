"""Reference fix: server-side request forgery.

Why the hole existed
    The server fetched any http(s) URL a user gave it. The request is made from
    the server's position in the network, so it reaches things the user cannot:
    loopback services, the private network, cloud metadata endpoints
    (169.254.169.254), often with the server's own credentials attached.

Why this fix works
    The host is resolved to IP addresses the same way the HTTP client would
    resolve it, and the URL is rejected unless every address is a public one.
    Checking the resolved address, not the text, is what defeats the disguises:
    `localhost`, `2130706433`, `127.1`, `0x7f.0.0.1` and `[::ffff:127.0.0.1]`
    are all the same loopback address once resolved.

The secure pattern
    If the feature only needs a known set of partners, use an allowlist of exact
    hosts; that is stronger than any blocklist. If arbitrary public URLs are
    required: allow only http/https, resolve and check every address, connect to
    the address you checked (otherwise DNS can change between check and use),
    and do not follow redirects without re-checking each hop. "Not loopback" is
    not enough: private ranges (10/8, 192.168/16), link-local addresses and
    multicast must be refused too, which is why this checks for "public" instead. Run the fetcher
    with no ambient credentials, and firewall it from internal networks.
"""

import ipaddress
import socket
from urllib.parse import urlsplit


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%")[0])  # drop an IPv6 zone id
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def is_allowed_url(url: str) -> bool:
    """Decide whether the server may fetch `url` on a user's behalf."""
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not host:
        return False
    try:
        resolved = socket.getaddrinfo(host, port or 80, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return False
    return all(_is_public(info[4][0]) for info in resolved)
