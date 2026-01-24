from __future__ import annotations

import json
from typing import Any

NAME = "nikto"


def can_run(ctx: dict[str, Any]) -> bool:
    return bool(ctx.get("urls"))


def run(ctx: dict[str, Any], *, timeout: int, args: dict[str, Any] | None = None) -> dict[str, Any]:
    args = args or {}
    runner = ctx["run"]
    base_url = str(ctx["urls"][0])

    out = "/tmp/nikto.json"
    cmd = [
        "nikto",
        "-h",
        base_url,
        "-maxtime",
        str(args.get("maxtime", "2m")),
        "-timeout",
        str(args.get("per_request_timeout", 5)),
        "-Format",
        "json",
        "-output",
        out,
    ]

    runner(cmd, timeout=timeout)

    try:
        with open(out, "r") as f:
            return json.load(f)
    except Exception as e:
        try:
            with open(out, "r") as f:
                raw = f.read()[-2000:]
        except Exception:
            raw = ""
        return {"error": str(e), "raw_tail": raw}
