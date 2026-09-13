"""NostrHost core primitives: error hierarchy and interface registry.

Stage 1 of the moulinette removal.  This module owns the two things every
YunoHost module touches through moulinette that are not i18n or locking:

* ``NostrHostError`` and friends -- the native replacement for the
  ``MoulinetteError``/``MoulinetteValidationError``/
  ``MoulinetteAuthenticationError`` hierarchy the fork's ``YunohostError``
  family derives from.  The base keeps moulinette's ``http_code``,
  ``raw_msg``, ``strerror`` and ``content()`` contract so Stage 2 can swap
  the import without touching exception handling, and adds a machine-readable
  ``code``/``status`` for the operation layer.

* The interface registry -- ``Moulinette.interface`` /
  ``Moulinette._interface`` is how code decides "am I running as a CLI or an
  API" (``Moulinette.interface.type``) and how the CLI/API drivers hand the
  rest of the stack an object with ``prompt``/``display``.  ``Moulinette``
  below is a drop-in with the same class attributes; ``set_interface`` is the
  programmatic equivalent of assigning ``Moulinette._interface``.
"""

from __future__ import annotations

from typing import Any

from .i18n import tr


class NostrHostError(Exception):
    """Base exception for NostrHost, replacing ``MoulinetteError``.

    ``key`` is a translation key resolved through ``nostrhost.i18n.tr`` unless
    ``raw_msg`` is True, in which case it is the literal message.  Keeps
    moulinette's ``strerror`` and ``content()`` contract.
    """

    http_code = 500
    code = "nostrhost_error"
    status = 500

    def __init__(
        self,
        key: str,
        raw_msg: bool = False,
        log_ref: str | None = None,
        error_details: str | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self.key = key
        self.kwargs = kwargs
        self.log_ref = log_ref
        self.error_details = error_details
        msg = key if raw_msg else tr(key, *args, **kwargs)
        # Call Exception.__init__ directly (not super()): during the
        # transition the fork's YunohostError bridges NostrHostError with
        # moulinette's MoulinetteError via multiple inheritance, and routing
        # through the MRO would hit MoulinetteError.__init__, which would
        # re-translate the already-translated message.
        Exception.__init__(self, msg)
        self.strerror = msg

    def content(self) -> dict[str, str] | str:
        """Machine-readable body for the API layer.

        Mirrors the fork's ``YunohostError.content``: a structured dict when
        a log ref or details are attached, otherwise the plain message.
        """
        if self.log_ref:
            return {"error": self.strerror, "log_ref": self.log_ref}
        if self.error_details:
            return {"error": self.strerror, "details": self.error_details}
        return self.strerror


class NostrHostValidationError(NostrHostError):
    """Invalid request/arguments (HTTP 400)."""

    http_code = 400
    code = "validation_error"
    status = 400

    def content(self) -> dict[str, str]:
        return {"error": self.strerror, "error_key": self.key, **self.kwargs}


class AuthenticationError(NostrHostError):
    """Authentication required or failed (HTTP 401)."""

    http_code = 401
    code = "authentication_error"
    status = 401


class AuthorisationError(NostrHostError):
    """The caller is authenticated but not allowed (HTTP 403)."""

    http_code = 403
    code = "authorisation_error"
    status = 403


class LockAcquireTimeout(NostrHostError):
    """A lock could not be acquired within the timeout."""

    code = "lock_timeout"
    status = 500


# --------------------------------------------------------------------------- #
# interface registry
#
# ``Moulinette._interface`` is the single source of truth: the fork assigns it
# directly (the headless-daemon pattern), and ``set_interface``/``interface``
# read and write the same attribute so both access styles stay in sync.  The
# former transition bridge to the (now retired) moulinette framework is gone.


class _ClassProperty:
    """Descriptor so ``Moulinette.interface`` works at class level, matching
    moulinette's ``classproperty``."""

    def __init__(self, f: Any) -> None:
        self._f = f

    def __get__(self, obj: Any, owner: Any) -> Any:
        return self._f(owner)


class Moulinette:
    """Drop-in for ``moulinette.Moulinette`` used across the fork.

    The fork references ``Moulinette.interface.type`` and assigns
    ``Moulinette._interface`` (see ``nostr_identity._init_headless_yunohost``),
    and calls ``Moulinette.prompt``/``Moulinette.display``.  All four are
    preserved here; the CLI/API drivers keep the same shape.
    """

    _interface: Any = None

    @_ClassProperty
    def interface(cls: Any) -> Any:
        return cls._interface

    @staticmethod
    def prompt(*args: Any, **kwargs: Any) -> Any:
        return Moulinette._interface.prompt(*args, **kwargs)

    @staticmethod
    def display(*args: Any, **kwargs: Any) -> Any:
        return Moulinette._interface.display(*args, **kwargs)

    @staticmethod
    def confirm(*args: Any, **kwargs: Any) -> Any:
        return Moulinette._interface.confirm(*args, **kwargs)

    @staticmethod
    def ask(*args: Any, **kwargs: Any) -> Any:
        return Moulinette._interface.ask(*args, **kwargs)


class _InterfaceProxy:
    """Attribute-forwarding view of the active interface for new code.

    ``nostrhost.core.interface.type`` reads ``Moulinette._interface.type``;
    accessing attributes before an interface is registered raises a clear
    error rather than ``AttributeError: 'NoneType'``.
    """

    def __getattr__(self, name: str) -> Any:
        if Moulinette._interface is None:
            raise RuntimeError(
                "no interface registered: call nostrhost.core.set_interface() "
                "before using nostrhost.core.interface"
            )
        return getattr(Moulinette._interface, name)

    def __repr__(self) -> str:
        return f"<interface proxy: {Moulinette._interface!r}>"


interface = _InterfaceProxy()


def set_interface(obj: Any) -> None:
    """Register the active interface (``type`` + ``prompt``/``display``)."""
    Moulinette._interface = obj


def get_interface() -> Any:
    """Return the active interface, or None when unset (headless mode)."""
    return Moulinette._interface
