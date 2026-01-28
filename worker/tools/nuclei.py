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

    artifact_path = ctx.get("artifact_path")

    # Bound scan size so runs finish deterministically.
    max_katana = int(args.get("max_katana_urls", 2000))
    max_targets = int(args.get("max_targets", 2500))

    targets = base_urls + katana_urls[: max(0, max_katana)] + ffuf_urls

    # De-dupe while preserving order.
    seen: set[str] = set()
    urls: list[str] = []
    for u in targets:
        if u in seen:
            continue
        seen.add(u)
        urls.append(u)
        if len(urls) >= max(1, max_targets):
            break

    if not urls:
        # Fallback to original scan target if present.
        target_url = str(ctx.get("target") or "").strip()
        if target_url:
            urls = [target_url]

    if not urls:
        return {"count": 0, "inserted_findings": 0, "scanned_urls": 0}

    targets_path = None
    if artifact_path:
        targets_path = str(Path(str(artifact_path)).with_name("nuclei_targets.txt"))
    else:
        targets_path = "/tmp/targets.txt"

    try:
        with open(str(targets_path), "w", encoding="utf-8", errors="replace") as f:
            f.write("\n".join(urls) + "\n")
    except Exception:
        # If we can't write a list file, fall back to a single target.
        targets_path = None

    # Prefer fast defaults unless overridden.
    fast_mode = bool(ctx.get("fast_mode"))
    templates = args.get("templates")
    if not templates and fast_mode:
        templates = "/opt/nuclei-templates/http/exposures/"

    # Clamp concurrency by scan cap if present.
    concurrency = args.get("concurrency")
    if concurrency is None:
        concurrency = 10 if fast_mode else 25
    try:
        concurrency = int(concurrency)
    except Exception:
        concurrency = 10

    cap = ctx.get("concurrency_cap")
    if cap is not None:
        try:
            concurrency = min(concurrency, int(cap))
        except Exception:
            pass

    rate_limit = args.get("rate_limit")
    if rate_limit is None:
        rate_limit = 10 if fast_mode else 50

    req_timeout = args.get("timeout")
    if req_timeout is None:
        req_timeout = 5 if fast_mode else 10

    retries = args.get("retries")
    if retries is None:
        retries = 1 if fast_mode else 2

    cmd = ["nuclei", "-jsonl", "-silent", "-duc"]
    if templates:
        cmd += ["-t", str(templates)]
    cmd += ["-rate-limit", str(rate_limit)]
    cmd += ["-timeout", str(req_timeout)]
    cmd += ["-retries", str(retries)]
    cmd += ["-c", str(concurrency)]

    if targets_path:
        cmd += ["-l", str(targets_path)]
    else:
        cmd += ["-u", str(urls[0])]

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
    insert_findings_bulk = ctx.get("insert_findings_bulk")
    scan_id = str(ctx.get("scan_id") or "")
    tool_run_id = ctx.get("tool_run_id")
    attempt = ctx.get("tool_attempt")

    include_raw = bool(args.get("include_raw", not fast_mode))

    payloads: list[dict[str, Any]] = []
    if scan_id and tool_run_id:
        for f in findings:
            info = (f.get("info") or {}) if isinstance(f, dict) else {}
            payload: dict[str, Any] = {
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
            }
            if include_raw:
                payload["raw"] = f
            payloads.append(payload)

    if payloads and callable(insert_findings_bulk):
        try:
            inserted = int(insert_findings_bulk(scan_id, "nuclei", payloads))
        except Exception:
            inserted = 0
    elif payloads and callable(insert_finding):
        for payload in payloads:
            try:
                if insert_finding(scan_id, "nuclei", payload):
                    inserted += 1
            except Exception:
                pass

    return {
        "count": len(findings),
        "inserted_findings": inserted,
        "scanned_urls": len(urls),
        "max_targets": max_targets,
        "max_katana_urls": max_katana,
        "used_templates": templates,
        "rate_limit": rate_limit,
        "concurrency": concurrency,
    }
