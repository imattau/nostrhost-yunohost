"""Native authenticator base (Moulinette ``BaseAuthenticator`` replacement).

The fork's LDAP authenticators subclass ``moulinette.authentication.
BaseAuthenticator``; the moulinette API framework instantiates them and calls
``authenticate_credentials`` / ``set_session_cookie`` / ``get_session_cookie``
/ ``delete_session_cookie``.  This module provides the same base contract with
native errors so the authenticators stop importing moulinette.
"""

from __future__ import annotations

import logging
from typing import Any

from ..core import AuthenticationError, NostrHostError

logger = logging.getLogger("nostrhost.auth")


class BaseAuthenticator:
    """Authenticator base representation.

    Subclasses must define ``name`` and implement ``_authenticate_credentials``
    (plus the session-cookie methods the API framework calls).  ``authenticate_credentials``
    mirrors moulinette: it delegates to ``_authenticate_credentials`` and wraps
    unexpected failures in ``AuthenticationError("unable_authenticate")``,
    letting native ``NostrHostError`` exceptions propagate unchanged.
    """

    #: Profile name identifying this authenticator (set by subclasses).
    name: str = ""

    def authenticate_credentials(self, credentials: Any) -> Any:
        try:
            auth_info = self._authenticate_credentials(credentials) or {}
        except NostrHostError:
            raise
        except Exception as exc:  # noqa: BLE001 - mirror moulinette behaviour
            logger.exception(f"authentication {self.name} failed because '{exc}'")
            raise AuthenticationError("unable_authenticate")

        return auth_info

    def _authenticate_credentials(self, credentials: Any) -> Any:
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement _authenticate_credentials"
        )