"""Lightweight test bootstrap for the Nostr identity module.

The main tests/conftest.py pulls in the full moulinette stack; these tests
only need the fork's own package importable. The fork's `src/` directory IS
the `yunohost` package (debian installs it as such), so we alias it here.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
_pkg = types.ModuleType("yunohost")
_pkg.__path__ = [str(_SRC)]  # type: ignore[attr-defined]
sys.modules["yunohost"] = _pkg
