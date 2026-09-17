"""Trust-policy helpers for native domains.

External trust by default: only special-use TLDs that cannot be ACME
validated fall back to Caddy's internal CA (``tls internal``); every other
domain leaves TLS to Caddy's automatic HTTPS so real certificates are served
without per-domain setup.
"""

from __future__ import annotations

# Mirrors yunohost.utils.dns.SPECIAL_USE_TLDS. Kept local (dependency-free)
# because that module imports dnspython, which must not be required to render
# a Caddy snippet or to run the native test suite.
SPECIAL_USE_TLDS = ("home.arpa", "internal", "local", "localhost", "onion", "test")


def is_internal_trust_domain(domain: str) -> bool:
    """True for special-use TLDs that get the Caddy internal CA.

    ``.test``/``.local``/``.localhost``/``.internal``/``.home.arpa``/
    ``.onion`` cannot be ACME validated, so they render ``tls internal``;
    everything else gets external trust (Caddy automatic HTTPS / ACME).
    """
    name = domain.strip().lower().rstrip(".")
    return any(name.endswith(f".{tld}") for tld in SPECIAL_USE_TLDS)
