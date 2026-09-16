"""Structured, bounded problem log for the HTTP layers.

The native HTTP servers (:mod:`nostrhost.api`, :mod:`nostrhost.portal_api`)
write one JSON object per problem to ``/var/log/nostrhost/problems.log``:
every 4xx/5xx response and every unhandled exception, with request context
(method, route, status, error code, actor, request id, duration) and, for
server errors, the traceback. The file is bounded by in-process rotation, and
the allowlisted introspection tool ``logs.problems`` (scope ``logs.read``)
reads it back for the MCP / ``nostr-opctl``.

Records carry ``request_id`` (client-provided ``X-Nostrhost-Request-Id`` or a
generated id echoed on the response header) so a problem can be correlated
back to a specific browser/admin request.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
import logging.handlers
import os
import secrets
import time
from typing import Any

from fastapi import Request
from starlette.responses import Response

PROBLEMS_LOG = os.environ.get("NOSTRHOST_PROBLEMS_LOG", "/var/log/nostrhost/problems.log")
MAX_BYTES = 16 * 1024 * 1024
BACKUP_COUNT = 3
MAX_TRACEBACK = 32_000

_logger = logging.getLogger("nostrhost.problems")
_configured = False


class _JsonMessageFormatter(logging.Formatter):
    """Emit the record's message verbatim (already one JSON object per line)."""

    def format(self, record: logging.LogRecord) -> str:
        return record.getMessage()


def _ensure_configured() -> None:
    """Idempotently attach the bounded JSONL handler on first use."""
    global _configured
    # yunohost's init_logging configures the tree with
    # ``disable_existing_loggers=True``; a problem logger created or disabled
    # before that would otherwise go silent. Re-enable defensively on every
    # record so the diagnostics surface can never be lost to logger config.
    _logger.disabled = False
    if _configured:
        return
    path = PROBLEMS_LOG
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        for existing in list(_logger.handlers):
            _logger.removeHandler(existing)
            existing.close()
        handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT
        )
        handler.setFormatter(_JsonMessageFormatter())
        _logger.addHandler(handler)
        _logger.setLevel(logging.INFO)
        _logger.propagate = False
        _configured = True
    except OSError:  # pragma: no cover - logging must never break a request
        _configured = False


def configure(log_path: str | None = None) -> None:
    """(Re)point the problem log at ``log_path`` (tests / alternate layout)."""
    global PROBLEMS_LOG, _configured
    if log_path:
        PROBLEMS_LOG = log_path
    _configured = False
    _ensure_configured()


def _redact(value: str) -> str:
    try:
        from nostrhost_policy.redaction import redact_text
    except Exception:  # noqa: BLE001 - policy package unavailable
        return value
    try:
        return redact_text(value)
    except Exception:  # pragma: no cover - never break a request on redaction
        return value


def request_id(request: Request) -> str:
    """The request's correlation id (client-supplied or generated)."""
    existing = getattr(request.state, "request_id", None)
    if existing:
        return existing
    rid = request.headers.get("x-nostrhost-request-id") or secrets.token_hex(8)
    request.state.request_id = rid
    return rid


def attach_request_id(response: Response, request: Request) -> Response:
    if isinstance(response, Response):
        response.headers["X-Nostrhost-Request-Id"] = request_id(request)
    return response


def _error_code_message(exc: BaseException | None, status: int) -> tuple[str, str]:
    if exc is not None:
        code = getattr(exc, "code", None)
        message = getattr(exc, "message", None) or str(exc)
        if code:
            return code, _redact(str(message))
        if status >= 500:
            return "internal_error", "internal server error"
    return "http_error", f"HTTP {status}"


def record(
    request: Request,
    *,
    status: int | None = None,
    code: str,
    message: str,
    kind: str = "http",
    source: str = "api",
    duration_ms: float | None = None,
    exc: BaseException | None = None,
) -> None:
    """Write one structured problem record. Never raises.

    ``status`` is the HTTP status for server-side problems; client-side SPA
    reports have no HTTP status and pass ``None``.
    """
    try:
        _ensure_configured()
        entry: dict[str, Any] = {
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "request_id": request_id(request),
            "method": request.method,
            "path": request.url.path,
            "host": request.headers.get("host"),
            "remote": request.client.host if request.client else None,
            "actor": getattr(request.state, "admin_pubkey", None) or "anonymous",
            "status": status,
            "code": code,
            "kind": kind,
            "source": source,
            "message": _redact(str(message)),
            "duration_ms": round(duration_ms, 1) if duration_ms is not None else None,
        }
        if exc is not None and (status or 0) >= 500:
            import traceback

            entry["exc_type"] = type(exc).__name__
            entry["traceback"] = _redact("".join(traceback.format_exception(exc))[:MAX_TRACEBACK])
        _logger.info(json.dumps(entry, default=str))
    except Exception:  # pragma: no cover - logging must never break a request
        pass


def finalize(
    response: Response,
    request: Request,
    *,
    started: float | None = None,
    exc: BaseException | None = None,
    kind: str = "http",
    source: str = "api",
) -> Response:
    """Attach the request id and record a problem for any 4xx/5xx response."""
    try:
        attach_request_id(response, request)
        status = getattr(response, "status_code", 200)
        if status >= 400:
            code, message = _error_code_message(exc, status)
            duration_ms = (time.perf_counter() - started) * 1000 if started is not None else None
            record(
                request,
                status=status,
                code=code,
                message=message,
                kind=kind,
                source=source,
                duration_ms=duration_ms,
                exc=exc,
            )
    except Exception:  # pragma: no cover - logging must never break a request
        pass
    return response
