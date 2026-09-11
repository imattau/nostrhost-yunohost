"""NostrHost-specific extensions.

Native replacements for the framework primitives the fork used to get from
moulinette, plus the native administration surface:

* ``nostrhost.i18n``     -- translations, ``colorize``, ``get_locale``
* ``nostrhost.core``     -- error hierarchy + interface registry
* ``nostrhost.locking``  -- flock-based ``LockManager``
* ``nostrhost.logging``  -- ``getActionLogger`` + TTY handler
* ``nostrhost.ui``       -- prompt/display + result presentation
* ``nostrhost.cli``      -- the native ``nostrhost`` Typer CLI
* ``nostrhost.api``      -- the native HTTP API (NIP-98 auth)

Submodules are imported explicitly by callers; this package intentionally does
not eagerly import them so ``import nostrhost`` stays dependency-light.
"""
