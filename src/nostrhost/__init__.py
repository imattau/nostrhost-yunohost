"""NostrHost-specific YunoHost extensions.

Stage 1 of the moulinette removal adds native replacements for the Moulinette
primitives the fork depends on, so Stage 2 can swap imports mechanically:

* ``nostrhost.i18n``    -- ``m18n`` / ``colorize`` / ``get_locale``
* ``nostrhost.core``    -- error hierarchy + ``Moulinette`` interface registry
* ``nostrhost.locking`` -- ``MoulinetteLock`` (flock-based ``LockManager``)
* ``nostrhost.logging`` -- ``getActionLogger``
* ``nostrhost.ui``      -- ``Moulinette.prompt`` / ``display``
* ``nostrhost.models``  -- typed operation/argument/result schemas

Submodules are imported explicitly by callers; this package intentionally does
not eagerly import them so ``import nostrhost`` stays dependency-light.
"""