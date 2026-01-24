from __future__ import annotations

import json
from typing import Any

NAME = "nuclei"


def can_run(ctx: dict[str, Any]) -> bool:
    return bool(ctx.get("urls"))


def run(ctx: dict[str, Any], *, timeout: int, args: dict[str, Any] | None = None) -> dict[str, Any]:
    args = args or {}
    runner = ctx["run"]
    urls: list[str] = list(ctx.get("urls") or [])

    with open("/tmp/targets.txt", "w") as f:
        f.write("\n".join(urls) + "\n")

    fast_mode = bool(ctx.get("fast_mode"))
    if fast_mode:
        cmd = [
            "nuclei",
            "-l",
            "/tmp/targets.txt",
            "-jsonl",
            "-silent",
            "-t",
            str(args.get("templates", "http/exposures/")),
            "-rate-limit",
            str(args.get("rate_limit", 10)),
            "-timeout",
            str(args.get("timeout", 5)),
            "-retries",
            str(args.get("retries", 1)),
            "-c",
            str(args.get("concurrency", 10)),
        ]
    else:
        cmd = ["nuclei", "-l", "/tmp/targets.txt", "-jsonl", "-silent"]

    nuclei_json = runner(cmd, timeout=timeout)

    findings: list[dict[str, Any]] = []
    for line in nuclei_json.splitlines():
        try:
            findings.append(json.loads(line))
        except Exception:
            pass

    return {"count": len(findings), "findings": findings}
