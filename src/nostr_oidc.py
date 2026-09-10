"""Small OIDC compatibility provider backed by the portal session.

This is intentionally an application-compatibility bridge, not a second
identity store.  Clients are configured in ``/etc/nostrhost/oidc.toml`` and
the authenticated subject is resolved from the existing portal cookie.
Authorization codes are short-lived and single-use; signing keys are kept in
the state directory and are exposed only through the public JWKS document.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import tomllib
from pathlib import Path
from urllib.parse import urlencode

import jwt
from bottle import HTTPResponse, redirect, request, response

ISSUER = os.environ.get("NOSTRHOST_OIDC_ISSUER")
CONFIG_PATH = "/etc/nostrhost/oidc.toml"
# The portal API is intentionally unprivileged; its signing key belongs in
# its writable, persistent cache directory rather than the root-owned state
# directory used by control-plane services.
KEY_PATH = os.environ.get(
    "NOSTRHOST_OIDC_KEY", "/var/cache/yunohost-portal/sessions/oidc-signing.pem"
)
CODE_TTL = 60
_codes: dict[str, dict] = {}
_private_key: bytes | None = None


def _config() -> dict:
    try:
        with open(CONFIG_PATH, "rb") as fh:
            return tomllib.load(fh)
    except (FileNotFoundError, tomllib.TOMLDecodeError):
        return {"clients": {}}


def _issuer() -> str:
    """Return the configured issuer, or derive it from the current host."""
    if ISSUER:
        return ISSUER.rstrip("/")
    scheme = request.get_header("X-Forwarded-Proto") or request.urlparts.scheme
    return f"{scheme}://{request.urlparts.netloc}"


def _clients() -> dict:
    clients = _config().get("clients", {})
    return clients if isinstance(clients, dict) else {}


def _client(client_id: str, redirect_uri: str) -> dict:
    client = _clients().get(client_id)
    if not isinstance(client, dict) or redirect_uri not in client.get("redirect_uris", []):
        raise HTTPResponse(status=400, body="invalid_client or redirect_uri")
    return client


def _session() -> dict:
    from .authenticators.ldap_ynhuser import Authenticator

    try:
        session = Authenticator().get_session_cookie()
    except Exception as exc:
        raise HTTPResponse(status=401, body="login_required") from exc
    if not session or not session.get("user"):
        raise HTTPResponse(status=401, body="login_required")
    return session


def _load_key() -> bytes:
    global _private_key
    if _private_key is None:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        path = Path(KEY_PATH)
        try:
            _private_key = path.read_bytes()
        except FileNotFoundError:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            _private_key = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(_private_key)
            os.chmod(path, 0o600)
    return _private_key


def _public_jwk() -> dict:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(_load_key(), password=None)
    numbers = key.public_key().public_numbers()

    def b64(value: int) -> str:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    jwk = {"kty": "RSA", "n": b64(numbers.n), "e": b64(numbers.e), "alg": "RS256", "use": "sig"}
    jwk["kid"] = hashlib.sha256(json.dumps(jwk, sort_keys=True).encode()).hexdigest()[:16]
    return jwk


def _token(claims: dict) -> str:
    now = int(time.time())
    jwk = _public_jwk()
    return jwt.encode(
        {**claims, "iss": _issuer(), "iat": now, "exp": now + 300},
        _load_key(),
        algorithm="RS256",
        headers={"kid": jwk["kid"]},
    )


def discovery():
    return {
        "issuer": _issuer(),
        "authorization_endpoint": f"{_issuer()}/oidc/authorize",
        "token_endpoint": f"{_issuer()}/oidc/token",
        "userinfo_endpoint": f"{_issuer()}/oidc/userinfo",
        "jwks_uri": f"{_issuer()}/oidc/jwks.json",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
    }


def jwks():
    return {"keys": [_public_jwk()]}


def authorize():
    client_id = request.query.client_id
    redirect_uri = request.query.redirect_uri
    response_type = request.query.response_type
    scope = set((request.query.scope or "").split())
    if response_type != "code" or "openid" not in scope:
        raise HTTPResponse(status=400, body="unsupported authorization request")
    _client(client_id, redirect_uri)
    session = _session()
    code = secrets.token_urlsafe(32)
    _codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "session": session,
        "nonce": request.query.nonce,
        "expires": time.time() + CODE_TTL,
    }
    params = {"code": code}
    if request.query.state:
        params["state"] = request.query.state
    return redirect(redirect_uri + ("&" if "?" in redirect_uri else "?") + urlencode(params))


def token():
    if request.forms.grant_type != "authorization_code":
        raise HTTPResponse(status=400, body="unsupported_grant_type")
    code = request.forms.code
    record = _codes.pop(code, None)
    if not record or record["expires"] < time.time():
        raise HTTPResponse(status=400, body="invalid_grant")
    if record["client_id"] != request.forms.client_id or record["redirect_uri"] != request.forms.redirect_uri:
        raise HTTPResponse(status=400, body="invalid_grant")
    client = _clients()[record["client_id"]]
    if request.forms.client_secret != client.get("client_secret"):
        raise HTTPResponse(status=401, body="invalid_client")
    session = record["session"]
    subject = hashlib.sha256(session["user"].encode()).hexdigest()
    access = secrets.token_urlsafe(32)
    _codes[access] = {"subject": subject, "session": session, "expires": time.time() + 300}
    claims = {"sub": subject, "aud": record["client_id"]}
    if record["nonce"]:
        claims["nonce"] = record["nonce"]
    return {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": _token(claims),
        "scope": " ".join(sorted(record["scope"])),
    }


def userinfo():
    auth = request.get_header("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPResponse(status=401, body="invalid_token")
    record = _codes.get(auth[7:])
    if not record or record["expires"] < time.time():
        raise HTTPResponse(status=401, body="invalid_token")
    session = record["session"]
    return {"sub": record["subject"], "preferred_username": session["user"], "email": session.get("email"), "name": session.get("fullname")}
