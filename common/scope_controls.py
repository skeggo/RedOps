from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from urllib.parse import urlparse


class ScopeError(ValueError):
    pass


@dataclass(frozen=True)
class Allowlist:
    domains: tuple[str, ...]
    services: tuple[str, ...]
    cidrs: tuple[ipaddress._BaseNetwork, ...]


def _split_items(raw: str) -> list[str]:
    # Allow comma / space / newline separated values.
    raw = (raw or "").strip()
    if not raw:
        return []

    normalized = raw.replace("\n", ",").replace(" ", ",").replace("\t", ",")
    items = [p.strip() for p in normalized.split(",")]
    return [i for i in items if i]


def load_allowlist(env_var: str = "SCAN_ALLOWLIST") -> Allowlist:
    raw = os.getenv(env_var, "")
    items = _split_items(raw)
    if not items:
        raise ScopeError(
            f"{env_var} is required and must be non-empty (example: 'example.com,1.2.3.0/24,juiceshop')"
        )

    domains: list[str] = []
    services: list[str] = []
    cidrs: list[ipaddress._BaseNetwork] = []

    for item in items:
        i = item.strip()
        if not i:
            continue

        # Optional prefixes for clarity.
        for prefix in ("domain:", "cidr:", "svc:", "service:", "host:"):
            if i.lower().startswith(prefix):
                i = i[len(prefix) :].strip()
                break

        if "/" in i:
            try:
                cidrs.append(ipaddress.ip_network(i, strict=False))
                continue
            except Exception as e:
                raise ScopeError(f"Invalid CIDR in allowlist: {item} ({e})")

        # Normalize host-like tokens.
        i = i.rstrip(".").lower()

        # Treat single-label names as lab services (exact match only).
        if "." not in i and i not in ("localhost", "host.docker.internal"):
            services.append(i)
        else:
            domains.append(i)

    return Allowlist(domains=tuple(sorted(set(domains))), services=tuple(sorted(set(services))), cidrs=tuple(cidrs))


def _extract_host(target: str) -> str:
    t = (target or "").strip()
    if not t:
        raise ScopeError("Missing target")

    # Parse URL-ish strings.
    if "://" in t:
        u = urlparse(t)
        host = u.hostname
    elif "/" in t or ":" in t:
        # Might be host:port or host/path.
        u = urlparse("http://" + t)
        host = u.hostname
    else:
        host = t

    host = (host or "").strip().rstrip(".").lower()
    if not host:
        raise ScopeError("Invalid target (could not extract host)")
    return host


def _resolve_ips(host: str) -> list[ipaddress._BaseAddress]:
    # IP literal?
    try:
        return [ipaddress.ip_address(host)]
    except Exception:
        pass

    ips: list[ipaddress._BaseAddress] = []
    try:
        for family, _type, _proto, _canonname, sockaddr in socket.getaddrinfo(host, None):
            if family == socket.AF_INET:
                ip = sockaddr[0]
            elif family == socket.AF_INET6:
                ip = sockaddr[0]
            else:
                continue
            try:
                ips.append(ipaddress.ip_address(ip))
            except Exception:
                continue
    except Exception:
        return []

    # Deduplicate while preserving order.
    seen: set[str] = set()
    out: list[ipaddress._BaseAddress] = []
    for ip in ips:
        s = str(ip)
        if s in seen:
            continue
        seen.add(s)
        out.append(ip)
    return out


def _host_matches_allowlist(host: str, allowlist: Allowlist) -> bool:
    # If host is an IP literal, check CIDRs only.
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in allowlist.cidrs)
    except Exception:
        pass

    # Service allowlist: exact match only.
    if host in allowlist.services:
        return True

    # Domain allowlist: exact match or subdomain match.
    for d in allowlist.domains:
        if not d:
            continue
        dom = d
        wildcard = False
        if dom.startswith("*."):
            wildcard = True
            dom = dom[2:]
        if dom.startswith("."):
            wildcard = True
            dom = dom[1:]

        if host == dom:
            return True
        if wildcard or "." in dom:
            if host.endswith("." + dom):
                return True

    return False


def _is_private_or_local(ip: ipaddress._BaseAddress) -> bool:
    # Be conservative: block anything that isn't globally routable.
    if getattr(ip, "is_global", None) is not None:
        return not ip.is_global

    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_target(
    target: str,
    *,
    allowlist: Allowlist,
    lab_mode: bool,
    resolver=_resolve_ips,
) -> dict:
    """Validate `target` against allowlist + private IP block.

    Returns a dict with:
      - host
      - resolved_ips (list[str])
      - warnings (list[str])
    """

    host = _extract_host(target)

    if not _host_matches_allowlist(host, allowlist):
        raise ScopeError(f"Target '{host}' is not in allowlist")

    ips = resolver(host)
    warnings: list[str] = []

    if not ips:
        warnings.append("dns_resolution_failed")
    else:
        blocked = [str(ip) for ip in ips if _is_private_or_local(ip)]
        if blocked and not lab_mode:
            raise ScopeError(
                "Target resolves to private/local IP(s) and LAB_MODE!=1: " + ",".join(blocked)
            )

    return {"host": host, "resolved_ips": [str(i) for i in ips], "warnings": warnings}
