from __future__ import annotations

import json
from typing import Any

NAME = "httpx"


def can_run(ctx: dict[str, Any]) -> bool:
    if ctx.get("mode") == "recon":
        return bool(ctx.get("subdomains"))
    if ctx.get("mode") == "url":
        return bool(ctx.get("target"))
    return False


def run(ctx: dict[str, Any], *, timeout: int, args: dict[str, Any] | None = None) -> dict[str, Any]:
    runner = ctx["run"]

    if ctx.get("mode") == "recon":
        subdomains: list[str] = list(ctx.get("subdomains") or [])
        cmd = ["httpx", "-silent", "-json"] + sum([["-u", s] for s in subdomains], [])
    else:
        target = str(ctx.get("target") or "").strip()
        cmd = ["httpx", "-silent", "-json", "-u", target]

    out = runner(cmd, timeout=timeout)

    artifact_path = ctx.get("artifact_path")
    if artifact_path:
        try:
            with open(str(artifact_path), "w", encoding="utf-8", errors="replace") as f:
                f.write(out)
                if out and not out.endswith("\n"):
                    f.write("\n")
        except Exception:
            pass

    results: list[dict[str, Any]] = []
    for line in out.splitlines():
        try:
            results.append(json.loads(line))
        except Exception:
            pass

    urls = [str(r.get("url")) for r in results if r.get("url")]
    # Downstream tools use ctx['urls'] as the list of live base URLs.
    ctx["urls"] = urls
    ctx["live_urls"] = urls
    return {"count": len(results), "results": results}
