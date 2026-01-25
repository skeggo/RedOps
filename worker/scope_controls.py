"""Worker-local compatibility shim.

The implementation lives in common/scope_controls.py so backend and worker share
one source of truth.
"""

from common import scope_controls as _impl

ipaddress = _impl.ipaddress

Allowlist = _impl.Allowlist
ScopeError = _impl.ScopeError

load_allowlist = _impl.load_allowlist

_resolve_ips = _impl._resolve_ips


def validate_target(
    target: str,
    *,
    allowlist: Allowlist,
    lab_mode: bool,
):
    return _impl.validate_target(target, allowlist=allowlist, lab_mode=lab_mode, resolver=_resolve_ips)

__all__ = [
    "Allowlist",
    "ScopeError",
    "load_allowlist",
    "validate_target",
    "_resolve_ips",
    "ipaddress",
]
