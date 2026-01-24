from __future__ import annotations

import json
from typing import Any

NAME = "httpx"


def can_run(ctx: dict[str, Any]) -> bool:
    return ctx.get("mode") == "recon" and bool(ctx.get("subdomains"))


def run(ctx: dict[str, Any], *, timeout: int, args: dict[str, Any] | None = None) -> dict[str, Any]:
    runner = ctx["run"]
    subdomains: list[str] = list(ctx.get("subdomains") or [])

    cmd = ["httpx", "-silent", "-json"] + sum([["-u", s] for s in subdomains], [])
    out = runner(cmd, timeout=timeout)

    results: list[dict[str, Any]] = []
    for line in out.splitlines():
        try:
            results.append(json.loads(line))
        except Exception:
            pass

    urls = [r.get("url") for r in results if r.get("url")]
    ctx["urls"] = urls
    return {"count": len(results), "results": results}
