from __future__ import annotations

from typing import Any

NAME = "direct_target"


def can_run(ctx: dict[str, Any]) -> bool:
    return ctx.get("mode") == "url" and bool(ctx.get("target"))


def run(ctx: dict[str, Any], *, timeout: int, args: dict[str, Any] | None = None) -> dict[str, Any]:
    # No external command; just set urls from the normalized target.
    url = str(ctx["target"])  # normalized in worker
    ctx["urls"] = [url]
    return {"urls": ctx["urls"]}
