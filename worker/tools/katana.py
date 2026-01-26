from __future__ import annotations

from urllib.parse import urldefrag
from typing import Any

NAME = "katana"


def can_run(ctx: dict[str, Any]) -> bool:
    # Expect live base URLs from httpx.
    return bool(ctx.get("urls"))


def _normalize_url(u: str) -> str | None:
    u = (u or "").strip()
    if not u:
        return None
    # Katana output can include non-URL lines depending on flags; keep only http(s).
    if not (u.startswith("http://") or u.startswith("https://")):
        return None
    # Remove fragments for stability.
    u, _frag = urldefrag(u)
    return u


def run(ctx: dict[str, Any], *, timeout: int, args: dict[str, Any] | None = None) -> dict[str, Any]:
    args = args or {}
    runner = ctx["run"]
    base_urls: list[str] = list(ctx.get("urls") or [])

    raw_lines: list[str] = []

    # Run per-base URL to avoid relying on less-common flags.
    for base in base_urls:
        base = str(base).strip()
        if not base:
            continue

        cmd = ["katana", "-u", base, "-silent"]

        # Optional depth control if present.
        depth = args.get("depth")
        if depth is not None:
            cmd += ["-d", str(depth)]

        out = runner(cmd, timeout=timeout)
        if out:
            raw_lines.extend(out.splitlines())

    # Normalize, dedupe, and cap.
    cap = int(args.get("max_urls", 10000))
    seen: set[str] = set()
    urls: list[str] = []

    for line in raw_lines:
        nu = _normalize_url(line)
        if not nu:
            continue
        if nu in seen:
            continue
        seen.add(nu)
        urls.append(nu)
        if len(urls) >= cap:
            break

    artifact_path = ctx.get("artifact_path")
    if artifact_path:
        try:
            with open(str(artifact_path), "w", encoding="utf-8", errors="replace") as f:
                for u in urls:
                    f.write(u + "\n")
        except Exception:
            pass

    ctx["katana_urls"] = urls
    return {"count": len(urls), "max_urls": cap}
