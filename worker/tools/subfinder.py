from __future__ import annotations

from typing import Any

NAME = "subfinder"


def can_run(ctx: dict[str, Any]) -> bool:
    return ctx.get("mode") == "recon" and bool(ctx.get("target"))


def run(ctx: dict[str, Any], *, timeout: int, args: dict[str, Any] | None = None) -> dict[str, Any]:
    runner = ctx["run"]
    domain = str(ctx["target"])

    out = runner(["subfinder", "-d", domain, "-silent"], timeout=timeout)
    subdomains = [s.strip() for s in out.splitlines() if s.strip()]
    ctx["subdomains"] = subdomains
    return {"count": len(subdomains), "subdomains": subdomains}
