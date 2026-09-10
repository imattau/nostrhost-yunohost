"""Nostr passwordless portal login (roadmap §8).

The portal keeps its normal LDAP/SSO session cookie, but users may sign in
passwordlessly by proving control of a pubkey that is linked (kind 31102) to
their YunoHost account. Flow:

    portal  --GET  /yunohost/portalapi/nostr/challenge-->  challenge nonce
    browser --sign a kind-22242 challenge event (NIP-07 / NIP-46 / passkey)
              with tags challenge / domain / action-->
    portal  --POST /yunohost/portalapi/nostr/login--> consume the challenge,
              verify signature + binding (nostrhost_auth), resolve the pubkey
              to an account via the identity store, then
              create_portal_session() (mints the yunohost.portal cookie)
    relay   <-- kind-2206 login notice, signed by the server key

Challenge state, session tokens and CSRF handling stay in the local HTTP
subsystem (never carried as Nostr events); the relay only records login
notices, exactly as the roadmap's §8 boundary requires.

Signature parsing/verification and challenge binding are delegated to
``nostrhost_auth.auth.nostr_verify`` (same library the MCP server uses for
the same job) rather than reimplemented here.
"""

import base64
import json
import logging
import os
import re
import time

logger = logging.getLogger("nostrhost-login")

LOGIN_ACTION = "yunohost-login"
NOTICE_KIND = 2206  # nostrhost auth/login notice
CHALLENGE_TTL = 90  # seconds a challenge stays valid (auth-lib default range)
CLOCK_SKEW = 60  # seconds of created_at tolerance
NOTICE_CONFIG = "/etc/nostrhost/portal.toml"  # ynh-portal-readable notice key
DEFAULT_CONTROL_RELAY = "ws://127.0.0.1:4848"


class LoginError(ValueError):
    """The passwordless login failed (signature, identity, permissions, …)."""


def _challenge_store():
    from nostrhost_auth.auth.challenge import ChallengeStore

    db_path = None  # challenge state stays in the local HTTP subsystem
    return ChallengeStore(ttl_seconds=CHALLENGE_TTL, db_path=db_path)


_challenges = _challenge_store()


def issue_challenge(domain: str) -> str:
    """Issue a fresh single-use login challenge bound to ``domain``."""
    return _challenges.issue(domain=domain, action=LOGIN_ACTION).nonce


# --------------------------------------------------------------------------- #
# session minting + login

def _user_infos_for_session(username: str) -> dict:
    from .utils.ldap import _get_ldap_interface

    result = _get_ldap_interface().search("ou=users", f"uid={username}", ["cn", "mail"])
    if not result:
        raise LoginError("no such user")
    return {"cn": result[0]["cn"][0], "mail": result[0]["mail"][0]}


def create_portal_session(username: str, *, domain: str | None = None) -> None:
    """Mint a passwordless ``yunohost.portal`` session cookie for ``username``.

    The session's ``pwd`` claim is an unbreakable sentinel: the user proved
    control of their key instead of a password, so the stored password cipher
    can never be used to bind to LDAP. The session carries ``passwordless`` so
    later phases can adapt password-dependent portal operations; any operation
    that truly needs the account password (e.g. changing it) keeps requiring
    the current password to be typed explicitly.
    """
    from bottle import request

    from .authenticators.ldap_ynhuser import (
        Authenticator,
        _host_domain,
        encrypt,
        user_is_allowed_on_domain,
    )
    from .utils.misc import random_ascii

    host = request.get_header("host")
    if domain is None:
        domain = host
    if not domain:
        raise LoginError("missing Host header")

    if not user_is_allowed_on_domain(username, _host_domain(domain)):
        raise LoginError("user is not allowed on this domain")

    infos = _user_infos_for_session(username)
    Authenticator().set_session_cookie(
        {
            "user": username,
            "pwd": encrypt(random_ascii(24)),
            "email": infos["mail"],
            "fullname": infos["cn"],
            "passwordless": True,
        }
    )


def _notice_config() -> dict | None:
    """Read the portal's dedicated notice config (portal.toml), or None.

    The portal-api service runs as a low-privilege user (ynh-portal) and must
    not hold the operator/server keys that live in root-only operator.toml, so
    login notices are signed with a dedicated key the bootstrap writes to a
    portal-readable file instead (alongside the control-relay URL). Missing or
    unreadable config degrades the notice to a no-op (the login itself never
    depends on it)."""
    import tomllib

    path = os.environ.get("NOSTRHOST_NOTICE_CONFIG", NOTICE_CONFIG)
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except Exception:
        return None


def _notice_signer() -> tuple[str, str] | None:
    """Return the portal's dedicated (sk, pubkey) notice key, or None."""
    from coincurve import PublicKeyXOnly

    conf = _notice_config()
    if not conf:
        return None
    sk = conf.get("notice_sk")
    if not isinstance(sk, str) or not _is_hex64(sk):
        return None
    pk = PublicKeyXOnly.from_secret(bytes.fromhex(sk)).format().hex()
    return sk, pk


def _is_hex64(s: str) -> bool:
    return len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s)


def _publish_login_notice(pubkey: str, username: str) -> None:
    try:
        from .nostr_identity import _sign_event, publish_to_relay

        notice = _notice_signer()
        if notice is None:
            logger.debug("no notice key configured; skipping login notice for %s", username)
            return
        conf = _notice_config() or {}
        relay = (
            conf.get("control_relay")
            or os.environ.get("NOSTRHOST_CONTROL_RELAY")
            or DEFAULT_CONTROL_RELAY
        )
        sk, pk = notice
        event = _sign_event(
            sk,
            pk,
            NOTICE_KIND,
            json.dumps({"username": username, "at": int(time.time())}),
            [["p", pubkey]],
        )
        publish_to_relay(relay, event)
    except Exception as e:  # the login must not fail because the notice did
        logger.warning("failed to publish login notice for %s: %s", username, e)


def handle_login(event: dict, *, domain: str, identity_db=None) -> dict:
    """Full passwordless login: consume + verify challenge, resolve, mint,
    notice. ``event`` is the raw NIP-01 event dict from the request body."""
    from nostrhost_auth.auth.nostr_verify import (
        InvalidEvent,
        extract_tag_from_raw_event,
        verify_challenge_response,
    )

    from .nostr_identity import resolve_pubkey

    nonce = extract_tag_from_raw_event(event, "challenge")
    if not nonce:
        raise LoginError("missing challenge tag")

    challenge = _challenges.consume(nonce)
    if challenge is None:
        raise LoginError("invalid or expired challenge")
    if challenge.domain != domain:
        raise LoginError("challenge was issued for a different domain")
    if challenge.action != LOGIN_ACTION:
        raise LoginError("challenge was issued for a different action")

    try:
        pubkey = verify_challenge_response(
            json.dumps(event),
            expected_nonce=challenge.nonce,
            expected_domain=challenge.domain,
            expected_action=challenge.action,
            issued_at=challenge.issued_at,
            expires_at=challenge.expires_at,
            clock_skew=CLOCK_SKEW,
        )
    except InvalidEvent as e:
        raise LoginError(str(e)) from e

    identity = resolve_pubkey(pubkey, db_path=identity_db)
    if identity is None:
        raise LoginError("pubkey is not linked to any account (or the link is revoked)")

    create_portal_session(identity.username, domain=domain)
    _publish_login_notice(pubkey, identity.username)
    return {"ok": True, "user": identity.username, "pubkey": pubkey}


# --------------------------------------------------------------------------- #
# portalapi routes (registered by src/__init__.py::portalapi, skipping the
# default authenticator: these are public by design)

def challenge_route():
    from bottle import HTTPResponse, request

    host = request.get_header("host")
    if not host:
        raise HTTPResponse("Missing Host header", 400)
    return {"challenge": issue_challenge(domain=host)}


def login_route():
    from bottle import HTTPResponse, request

    body = request.json or {}
    event = body.get("event")
    if not isinstance(event, dict):
        raise HTTPResponse("Missing signed event", 400)
    host = request.get_header("host")
    if not host:
        raise HTTPResponse("Missing Host header", 400)
    try:
        return handle_login(event, domain=host)
    except LoginError as e:
        raise HTTPResponse(str(e), 401)


def _load_ssowat_permissions(conf_path="/etc/nostrhost/permissions.json") -> dict:
    """Permission map for the Caddy ``forward_auth`` decision.

    SSOwat is retired: the projection is generated by
    ``nostrhost.permissions`` (root side) from YunoHost's permission system and
    read here. During the transition it falls back to the legacy
    ``/etc/ssowat/conf.json`` so a deployment that has not regenerated the
    projection yet keeps working.
    """
    for candidate in (conf_path, "/etc/ssowat/conf.json"):
        try:
            with open(candidate) as f:
                conf = json.load(f)
            permissions = conf.get("permissions") or {}
            if isinstance(permissions, dict):
                if candidate.endswith("ssowat/conf.json"):
                    logger.warning("falling back to legacy ssowat conf for permissions")
                return permissions
        except FileNotFoundError:
            continue
        except Exception as e:
            logger.warning("unable to read permissions conf %s: %s", candidate, e)
    return {}


def _match_permission(permissions: dict, full_url: str):
    """Longest-matching permission for ``host + uri`` (mirrors ssowat access.lua).

    Returns ``(permission_id, permission_info)`` or ``None``. ``re:`` prefixes
    are treated as anchored regular expressions; plain prefixes are matched
    from the start of the URL.
    """
    best = None
    best_len = -1
    for name, info in permissions.items():
        for prefix in info.get("uris") or []:
            if not isinstance(prefix, str):
                continue
            if prefix.startswith("re:"):
                pattern = prefix[3:]
                if not pattern.startswith("^"):
                    pattern = "^" + pattern
                m = re.match(pattern, full_url)
                match_len = m.end() if m else -1
            elif full_url.startswith(prefix):
                match_len = len(prefix)
            else:
                match_len = -1
            if match_len > best_len:
                best_len = match_len
                best = (name, info)
    return best


def _portal_redirect(proto: str, host: str, uri: str, *, logged_in: bool) -> str:
    """Redirect location matching ssowat access.lua: login callback or deny."""
    portal = f"{proto}://{host}/yunohost/sso/"
    if logged_in:
        return f"{portal}?msg=access_denied"
    back = base64.urlsafe_b64encode(f"{proto}://{host}{uri}".encode()).decode()
    return f"{portal}?r={back}"


def _authorize(
    permissions: dict,
    full_url: str,
    proto: str,
    host: str,
    uri: str,
    username: str | None,
) -> tuple[str, str | None]:
    """Full authorization decision for a Caddy ``forward_auth`` subrequest.

    Mirrors ssowat access.lua sections 3-4 + 6:
      - no matching permission -> deny (redirect to the portal)
      - public permission      -> allow (no identity headers needed)
      - protected permission   -> cookie auth + allowed-users check; allow with
        identity headers, or redirect (login callback / access-denied)
    """
    perm = _match_permission(permissions, full_url)
    if perm is None:
        return ("redirect", _portal_redirect(proto, host, uri, logged_in=(username is not None)))
    _name, info = perm
    if info.get("public"):
        return ("allow", None)
    if username is None:
        return ("redirect", _portal_redirect(proto, host, uri, logged_in=False))
    if username in (info.get("users") or []):
        return ("allow", "identity")
    return ("redirect", _portal_redirect(proto, host, uri, logged_in=True))


def _identity_headers(infos, username: str) -> dict[str, str]:
    """Identity headers the auth front end copies to the app.

    Every header is always present (empty when unknown) so a ``copy_headers``
    front end unconditionally overwrites any client-supplied copy -- spoofing
    protection equivalent to the nginx ``proxy_set_header`` bridge. Headers
    must be returned on the response object itself: bottle drops headers set on
    the global ``response`` when a route returns a fresh ``HTTPResponse``.
    """
    infos = infos or {}
    headers = {
        "X-Remote-User": username,
        "X-Remote-Email": "",
        "X-Remote-Fullname": "",
        "X-Nostr-Pubkey": "",
        "X-Nostr-Npub": "",
    }
    for header, key in (
        ("X-Remote-Email", "email"),
        ("X-Remote-Fullname", "fullname"),
    ):
        value = infos.get(key)
        if isinstance(value, str):
            headers[header] = value

    # A session may predate Nostr linking, and the identity database may not
    # be readable during early boot.  Neither case should turn valid portal
    # authentication into a 5xx response.
    try:
        from .nostr_identity import resolve_username

        identity = next(iter(resolve_username(username)), None)
        if identity is not None:
            headers["X-Nostr-Pubkey"] = identity.pubkey
            try:
                from nostrhost_auth.identity.npub import hex_to_npub

                headers["X-Nostr-Npub"] = hex_to_npub(identity.pubkey)
            except Exception:
                logger.debug("unable to encode linked identity for %s", username)
    except Exception:
        logger.debug("unable to resolve linked identity for %s", username)

    return headers


def auth_request_route():
    """Authorize a portal-session request for ``auth_request`` front ends.

    Two modes, selected by whether the caller forwarded the original URI:

    - Caddy ``forward_auth`` (``X-Forwarded-Uri`` present): the full
      authorization decision -- permission matching, allowed users/groups,
      public routes, and the redirect-to-portal outcome -- plus the identity
      headers the front end copies to the application.
    - Legacy nginx ``auth_request`` (no ``X-Forwarded-Uri``): cookie-only
      validation, the nginx/SSOwat path performs the permission check itself.

    The endpoint deliberately returns no user content: a successful response
    is only an authorization signal, with the identity exposed through the
    compatibility headers expected by YunoHost applications.
    """
    from bottle import HTTPResponse, request

    from .authenticators.ldap_ynhuser import Authenticator, _host_domain

    fwd_uri = request.get_header("X-Forwarded-Uri")

    try:
        infos = Authenticator().get_session_cookie()
    except Exception:
        infos = None
    username = (infos or {}).get("user") if isinstance(infos, dict) else None
    if not isinstance(username, str) or not username:
        username = None

    if fwd_uri is not None:
        host = request.get_header("X-Forwarded-Host") or request.get_header("host") or ""
        proto = request.get_header("X-Forwarded-Proto") or "https"
        match_uri = fwd_uri.split("?", 1)[0]
        # Permission URIs in the SSOwat conf are bare DNS names (no port).
        action, detail = _authorize(
            _load_ssowat_permissions(),
            _host_domain(host) + match_uri,
            proto,
            host,
            fwd_uri,
            username,
        )
        if action == "redirect":
            raise HTTPResponse(status=302, headers={"Location": detail})
        if action == "allow" and username is not None:
            return HTTPResponse(status=204, headers=_identity_headers(infos, username))
        return HTTPResponse(status=204)

    if username is None:
        raise HTTPResponse(status=401)

    return HTTPResponse(status=204, headers=_identity_headers(infos, username))
