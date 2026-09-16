"""Per-request context for the NostrHost HTTP layers (FastAPI/uvicorn).

The admin API (:mod:`nostrhost.api`), the portal API
(:mod:`nostrhost.portal_api`), the portal handlers and the session
authenticator all need per-request state: the current request, cookies to
set/delete, and an optional status override.

Those modules were originally written against bottle's module-level
``request``/``response`` globals. This module provides the same ergonomics on
ASGI — a request ContextVar, a ``request``/``response`` proxy, an
``HTTPResponse`` exception for early error returns, and a pending-cookie queue
that each route wrapper drains onto the final response.
"""

from __future__ import annotations

import contextvars
import json as _json
from typing import Any
from urllib.parse import parse_qs

from fastapi import Request
from starlette.responses import RedirectResponse, Response

_UNSET = object()

_request: contextvars.ContextVar[Request] = contextvars.ContextVar("nostrhost_web_request")
_cookies: contextvars.ContextVar[list[tuple[str, str, str, dict[str, Any]]]] = contextvars.ContextVar(
    "nostrhost_web_cookies"
)
_status: contextvars.ContextVar[int | None] = contextvars.ContextVar("nostrhost_web_status")


def begin(request: Request) -> contextvars.Token:
    """Bind ``request`` and reset the per-request response state."""
    token = _request.set(request)
    _cookies.set([])
    _status.set(None)
    return token


def end(token: contextvars.Token) -> None:
    _request.reset(token)


def current_request() -> Request:
    return _request.get()


def set_cookie(name: str, value: str, **kwargs: Any) -> None:
    _cookies.get().append(("set", name, value, kwargs))


def delete_cookie(name: str, **kwargs: Any) -> None:
    _cookies.get().append(("delete", name, "", kwargs))


def get_status() -> int | None:
    return _status.get()


def set_status(status: int) -> None:
    _status.set(status)


def apply_cookies(response: Response) -> Response:
    for op, name, value, kwargs in _cookies.get():
        if op == "set":
            response.set_cookie(name, value, **kwargs)
        else:
            response.delete_cookie(name, **kwargs)
    return response


class HTTPResponse(Exception):
    """Early response used by the portal handlers (raised or returned).

    Mirrors bottle's ``HTTPResponse``: a ``body`` plus ``status`` and optional
    ``headers``. Raised instances are converted by the route wrapper.
    """

    def __init__(self, body: str = "", status: int = 200, headers: dict[str, Any] | None = None) -> None:
        super().__init__(body)
        self.body = body
        self.status = status
        self.headers = {key: value for key, value in (headers or {}).items() if value is not None}

    def to_response(self) -> Response:
        return Response(content=self.body, status_code=self.status, headers=self.headers)

    @property
    def status_code(self) -> int:
        """bottle-compatible alias for ``status``."""
        return self.status


def redirect(location: str, status: int = 302) -> Response:
    return RedirectResponse(location, status_code=status)


class _MultiDict:
    """Read-only mapping with bottle's FormsDict access style (``.get`` and
    attribute access), used for ``request.query`` / ``request.forms``."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def __getattr__(self, key: str) -> Any:
        return self._data.get(key)

    def __contains__(self, key: object) -> bool:
        return key in self._data

    def __iter__(self):
        return iter(self._data)


def _body_bytes(request: Request) -> bytes:
    return getattr(request.state, "body_bytes", b"")


def json_body() -> Any:
    """The cached request body parsed as JSON (None when absent/malformed)."""
    request = current_request()
    if getattr(request.state, "json_body", _UNSET) is _UNSET:
        raw = _body_bytes(request)
        try:
            request.state.json_body = _json.loads(raw) if raw else None
        except (ValueError, TypeError):
            request.state.json_body = None
    return request.state.json_body


class _Request:
    @property
    def method(self) -> str:
        return current_request().method

    @property
    def headers(self):
        return current_request().headers

    @property
    def urlparts(self):
        return current_request().url

    @property
    def query(self) -> _MultiDict:
        return _MultiDict(dict(current_request().query_params))

    @property
    def forms(self) -> _MultiDict:
        request = current_request()
        if getattr(request.state, "form_body", None) is None:
            raw = _body_bytes(request).decode("utf-8", "replace")
            request.state.form_body = {key: values[-1] for key, values in parse_qs(raw).items()}
        return _MultiDict(request.state.form_body)

    @property
    def json(self) -> Any:
        return json_body()

    def get_header(self, name: str, default: Any = None) -> Any:
        return current_request().headers.get(name, default)

    def get_cookie(self, name: str, default: str = "") -> str:
        return current_request().cookies.get(name, default)


class _Response:
    def set_cookie(self, name: str, value: str, **kwargs: Any) -> None:
        set_cookie(name, value, **kwargs)

    def delete_cookie(self, name: str, **kwargs: Any) -> None:
        delete_cookie(name, **kwargs)

    @property
    def status(self) -> int | None:
        return get_status()

    @status.setter
    def status(self, value: int) -> None:
        set_status(value)


request = _Request()
response = _Response()
