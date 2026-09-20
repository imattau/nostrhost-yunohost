"""Compatibility module for the extracted projection framework (one release).

The shared projector framework moved to the ``nostrhost-projection`` library
(``nostrhost_projection``). This module re-exports the same names so existing
``yunohost.nostr_projector`` import paths keep working. New code should import
from :mod:`nostrhost_projection` directly.
"""

from __future__ import annotations

import warnings

from nostrhost_projection import (  # noqa: F401
    DEFAULT_CURSOR_DIR,
    MAX_FUTURE_SKEW,
    BACKOFF_SECONDS,
    Checkpoint,
    JsonCoordinateStore,
    ProjectionHealth,
    ProjectionRegistry,
    ProjectionResult,
    ProjectionRuntime,
    Projector,
    REGISTRY,
    StoreProjector,
    load_checkpoint,
    projection_events_for_health,
    read_status_dir,
    rebuild,
    save_checkpoint,
    shadow,
    sort_events,
    verify,
)
from nostrhost_projection.projector import _atomic_write  # noqa: F401

# The runtime used to default to the fork's operator-key auth. Preserve that
# default for the one-release compatibility window so existing callers that
# construct ProjectionRuntime without an explicit auth_factory keep working.
from .nostr_identity import default_auth as _default_auth

warnings.warn(
    "yunohost.nostr_projector is deprecated; import from nostrhost_projection",
    DeprecationWarning,
    stacklevel=2,
)


class ProjectionRuntimeCompat(ProjectionRuntime):
    """ProjectionRuntime with the fork's operator-auth default."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("auth_factory", _default_auth)
        super().__init__(*args, **kwargs)


ProjectionRuntime = ProjectionRuntimeCompat  # noqa: F811

__all__ = [
    "DEFAULT_CURSOR_DIR",
    "MAX_FUTURE_SKEW",
    "BACKOFF_SECONDS",
    "Checkpoint",
    "JsonCoordinateStore",
    "ProjectionHealth",
    "ProjectionRegistry",
    "ProjectionResult",
    "ProjectionRuntime",
    "Projector",
    "REGISTRY",
    "StoreProjector",
    "_atomic_write",
    "load_checkpoint",
    "projection_events_for_health",
    "read_status_dir",
    "rebuild",
    "save_checkpoint",
    "shadow",
    "sort_events",
    "verify",
]