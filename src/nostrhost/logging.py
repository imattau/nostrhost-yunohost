"""Native logging helpers (Moulinette ``moulinette.utils.log`` replacement).

The fork imports ``getActionLogger`` from ``moulinette.utils.log`` in exactly
one place (``migrations/0027_migrate_to_bookworm.py``) behind a try/except
that already falls back to ``logging.getLogger``.  Moulinette's historical
``getActionLogger`` returned a logger named ``action.<name>`` with an
operation formatter attached; for NostrHost a plain named logger is the
correct behaviour (the fork's own ``utils.logging`` configures the
``yunohost`` logger tree).  ``getActionLogger`` is kept so Stage 2 can drop
the import without touching that migration.
"""

from __future__ import annotations

import logging


def getActionLogger(name: str) -> logging.Logger:
    """Return the logger for an operation/action name."""
    return logging.getLogger(name)
