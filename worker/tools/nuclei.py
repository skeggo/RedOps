from __future__ import annotations

import json
from pathlib import Path
from typing import Any

NAME = "nuclei"


def can_run(ctx: dict[str, Any]) -> bool:
    return bool(ctx.get("urls"))


def run(ctx: dict[str, Any], *, timeout: int, args: dict[str, Any] | None = None) -> dict[str, Any]:
    args = args or {}
    runner = ctx["run"]

    base_urls: list[str] = [str(u) for u in (ctx.get("urls") or []) if str(u).strip()]
    katana_urls: list[str] = [str(u) for u in (ctx.get("katana_urls") or []) if str(u).strip()]
    ffuf_urls: list[str] = [str(u) for u in (ctx.get("ffuf_urls") or []) if str(u).strip()]

    # Bound the number of URLs scanned to keep the pipeline deterministic.
    max_katana = int(args.get("max_katana_urls", 2000))
    targets = base_urls + katana_urls[:max_katana] + ffuf_urls

    # De-dupe while preserving order.
    seen: set[str] = set()
    urls: list[str] = []
    for u in targets:
        if u in seen:
            continue
        seen.add(u)
        urls.append(u)

    artifact_path = ctx.get("artifact_path")
    targets_path = None
    if artifact_path:
        targets_path = str(Path(str(artifact_path)).with_name("nuclei_targets.txt"))
    else:
        targets_path = "/tmp/targets.txt"

    with open(str(targets_path), "w", encoding="utf-8", errors="replace") as f:
        f.write("\n".join(urls) + "\n")

    fast_mode = bool(ctx.get("fast_mode"))
    if fast_mode:
        cmd = [
            "nuclei",
            "-l",
            str(targets_path),
            "-jsonl",
            "-silent",
            "-duc",
            "-t",
            str(args.get("templates", "/opt/nuclei-templates/http/exposures/")),
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
        cmd = ["nuclei", "-l", str(targets_path), "-jsonl", "-silent", "-duc"]

    nuclei_json = runner(cmd, timeout=timeout)

    if artifact_path:
        try:
            with open(str(artifact_path), "w", encoding="utf-8", errors="replace") as f:
                f.write(nuclei_json)
                if nuclei_json and not nuclei_json.endswith("\n"):
                    f.write("\n")
        except Exception:
            pass

    findings: list[dict[str, Any]] = []
    for line in nuclei_json.splitlines():
        try:
            findings.append(json.loads(line))
        except Exception:
            pass

    inserted = 0
    insert_finding = ctx.get("insert_finding")
    scan_id = str(ctx.get("scan_id") or "")
    tool_run_id = ctx.get("tool_run_id")
    attempt = ctx.get("tool_attempt")

    if callable(insert_finding) and scan_id and tool_run_id:
        for f in findings:
            info = (f.get("info") or {}) if isinstance(f, dict) else {}
            payload = {
                "tool_run_id": tool_run_id,
                "attempt": attempt,
                "severity": info.get("severity"),
                "title": info.get("name") or f.get("template-id") or "nuclei finding",
                "template_id": f.get("template-id"),
                "matched_at": f.get("matched-at"),
                "host": f.get("host"),
                "type": f.get("type"),
                "tags": info.get("tags"),
                "reference": info.get("reference"),
                "description": info.get("description"),
                "matcher_name": f.get("matcher-name"),
                "extracted_results": f.get("extracted-results"),
                "curl_command": f.get("curl-command"),
                "raw": f,
            }
            try:
                insert_finding(scan_id, "nuclei", payload)
                inserted += 1
            except Exception:
                pass

    return {"count": len(findings), "inserted_findings": inserted, "scanned_urls": len(urls), "max_katana_urls": max_katana}
