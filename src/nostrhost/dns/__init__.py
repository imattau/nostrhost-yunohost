"""Native DNS subsystem (W4).

Typed DNS resources, the provider interface, ownership-bounded
reconciliation and a manual provider. The native domain plane owns
``DomainResource`` intent (``nostrhost.domains``); this module is the
record/provider/reconcile layer that materialises that intent against a DNS
provider.
"""
