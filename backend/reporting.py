from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Iterable, Mapping


def _iso(dt: datetime | None) -> str | None:
    if not dt:
        return None
    # Always emit an explicit UTC-ish ISO string; timestamps stored are UTC.
    return dt.replace(microsecond=0).isoformat() + "Z"


def _ms_between(started_at: datetime | None, finished_at: datetime | None) -> int | None:
    if not started_at or not finished_at:
        return None
    return int((finished_at - started_at).total_seconds() * 1000)


def _classify_finding_tool(tool: str) -> str:
    t = (tool or "").lower()
    if t.endswith("_skipped"):
        return "skipped"
    if t.endswith("_timeout"):
        return "timeout"
    if t.endswith("_error"):
        return "error"
    return "result"


def _extract_httpx_live_targets(findings_list: list[dict[str, Any]], *, limit: int = 50) -> list[str]:
    """Best-effort extraction of live URLs from the httpx tool's summary finding.

    We intentionally derive from DB-stored findings payloads rather than reading artifact files,
    so the backend stays stateless and doesn't need access to worker container paths.
    """

    urls: list[str] = []
    seen: set[str] = set()

    for f in findings_list:
        if str(f.get("tool") or "") != "httpx":
            continue
        payload = f.get("payload")
        if not isinstance(payload, dict):
            continue

        # Preferred: worker httpx wrapper stores parsed jsonl lines as payload['results'].
        results = payload.get("results")
        if isinstance(results, list):
            for r in results:
                if not isinstance(r, dict):
                    continue
                u = str(r.get("url") or "").strip()
                if not u or u in seen:
                    continue
                seen.add(u)
                urls.append(u)
                if len(urls) >= limit:
                    return urls

        # Fallback: some implementations might store 'live_urls' or 'urls'.
        for key in ("live_urls", "urls"):
            val = payload.get(key)
            if isinstance(val, list):
                for u0 in val:
                    u = str(u0 or "").strip()
                    if not u or u in seen:
                        continue
                    seen.add(u)
                    urls.append(u)
                    if len(urls) >= limit:
                        return urls

    return urls


def _extract_katana_endpoints(
    findings_list: list[dict[str, Any]],
    *,
    limit: int = 100,
) -> tuple[list[str], int | None, bool | None]:
    """Return (endpoints, total_count, truncated).

    Uses the latest katana summary finding payload.
    """

    # Prefer the latest katana run (findings are ordered by insertion time).
    for f in reversed(findings_list):
        if str(f.get("tool") or "") != "katana":
            continue
        payload = f.get("payload")
        if not isinstance(payload, dict):
            continue

        raw_urls = payload.get("urls")
        if not isinstance(raw_urls, list):
            raw_urls = payload.get("katana_urls")

        urls: list[str] = []
        seen: set[str] = set()
        if isinstance(raw_urls, list):
            for u0 in raw_urls:
                u = str(u0 or "").strip()
                if not u or u in seen:
                    continue
                seen.add(u)
                urls.append(u)
                if len(urls) >= limit:
                    break

        total_count = None
        try:
            total_count = int(payload.get("count")) if payload.get("count") is not None else None
        except Exception:
            total_count = None

        truncated = payload.get("urls_truncated")
        if not isinstance(truncated, bool):
            truncated = None

        return urls, total_count, truncated

    return [], None, None


def _severity_rank(sev: str) -> int:
    s = (sev or "").strip().lower()
    order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
        "informational": 4,
        "unknown": 5,
        "": 5,
    }
    return order.get(s, 5)


def _extract_nuclei_vulnerabilities(
    findings_list: list[dict[str, Any]],
    *,
    limit: int = 50,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Return (vulns, counts_by_severity).

    Only includes nuclei *result* findings (not summary/error markers).
    """

    vulns: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    counts: Counter[str] = Counter()

    for f in findings_list:
        if str(f.get("tool") or "") != "nuclei":
            continue
        payload = f.get("payload")
        if not isinstance(payload, dict):
            continue

        template_id = str(payload.get("template_id") or payload.get("template-id") or "").strip()
        matched_at = str(payload.get("matched_at") or payload.get("matched-at") or payload.get("host") or "").strip()
        title = str(payload.get("title") or payload.get("name") or "nuclei finding").strip()
        severity = str(payload.get("severity") or "unknown").strip().lower()

        # Skip the nuclei *summary* finding which doesn't include per-vuln fields.
        if not template_id and not matched_at:
            continue

        key = (template_id or title, matched_at)
        if key in seen:
            continue
        seen.add(key)

        counts[severity] += 1
        vulns.append(
            {
                "severity": severity,
                "title": title,
                "template_id": template_id or None,
                "matched_at": matched_at or None,
                "tool_run_id": payload.get("tool_run_id"),
            }
        )

    vulns_sorted = sorted(vulns, key=lambda v: (_severity_rank(str(v.get("severity") or "")), str(v.get("title") or ""), str(v.get("matched_at") or "")))
    if limit >= 0:
        vulns_sorted = vulns_sorted[:limit]

    # Return counts in stable order.
    counts_by_sev: dict[str, int] = {}
    for sev in ["critical", "high", "medium", "low", "info", "unknown"]:
        if counts.get(sev):
            counts_by_sev[sev] = int(counts[sev])
    # Include any other severities just in case.
    for sev, n in sorted(counts.items()):
        if sev not in counts_by_sev:
            counts_by_sev[sev] = int(n)

    return vulns_sorted, counts_by_sev


def compute_scan_summary(
    *,
    scan: Mapping[str, Any],
    tool_runs: Iterable[Mapping[str, Any]],
    findings: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    tool_runs_list = [dict(r) for r in tool_runs]
    findings_list = [dict(f) for f in findings]

    queued_ats: list[datetime] = [r["queued_at"] for r in tool_runs_list if r.get("queued_at")]
    started_ats: list[datetime] = [r["started_at"] for r in tool_runs_list if r.get("started_at")]
    finished_ats: list[datetime] = [r["finished_at"] for r in tool_runs_list if r.get("finished_at")]

    first_queued_at = min(queued_ats) if queued_ats else None
    first_started_at = min(started_ats) if started_ats else None
    last_finished_at = max(finished_ats) if finished_ats else None

    status_counts = Counter((r.get("status") or "unknown") for r in tool_runs_list)

    # Aggregate per tool, using the highest attempt as "latest".
    by_tool: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in tool_runs_list:
        by_tool[str(r.get("tool") or "unknown")].append(r)

    tools_summary: dict[str, Any] = {}
    for tool, runs in by_tool.items():
        runs_sorted = sorted(
            runs,
            key=lambda rr: (
                int(rr.get("attempt") or 0),
                rr.get("finished_at") or rr.get("started_at") or rr.get("queued_at") or datetime.min,
            ),
        )
        latest = runs_sorted[-1] if runs_sorted else {}
        total_duration_ms = sum(int(r.get("duration_ms") or 0) for r in runs_sorted)
        tools_summary[tool] = {
            "attempts": len(runs_sorted),
            "latest": {
                "id": latest.get("id"),
                "attempt": latest.get("attempt"),
                "status": latest.get("status"),
                "queued_at": latest.get("queued_at"),
                "started_at": latest.get("started_at"),
                "finished_at": latest.get("finished_at"),
                "duration_ms": latest.get("duration_ms"),
                "exit_code": latest.get("exit_code"),
                "short_error": latest.get("short_error"),
                "stdout_path": latest.get("stdout_path"),
                "stderr_path": latest.get("stderr_path"),
                "artifact_path": latest.get("artifact_path"),
                "args": latest.get("args"),
                "metadata": latest.get("metadata"),
            },
            "total_duration_ms": total_duration_ms,
            "status_counts": dict(Counter((r.get("status") or "unknown") for r in runs_sorted)),
        }

    findings_by_tool = Counter(str(f.get("tool") or "unknown") for f in findings_list)
    findings_by_category = Counter(_classify_finding_tool(str(f.get("tool") or "")) for f in findings_list)

    # Optional: MITRE ATT&CK mappings if present on findings.
    mitre_counts: Counter[str] = Counter()
    mitre_total = 0
    for f in findings_list:
        mitre = f.get("mitre")
        if not isinstance(mitre, list):
            continue
        for m in mitre:
            if not isinstance(m, dict):
                continue
            tid = str(m.get("technique_id") or "").strip()
            if not tid:
                continue
            mitre_total += 1
            mitre_counts[tid] += 1

    # A stable scan-level duration if possible.
    scan_duration_ms = _ms_between(first_started_at, last_finished_at)

    return {
        "scan": dict(scan),
        "timeline": {
            "created_at": scan.get("created_at"),
            "first_queued_at": first_queued_at,
            "first_started_at": first_started_at,
            "last_finished_at": last_finished_at,
            "duration_ms": scan_duration_ms,
        },
        "tool_runs": {
            "total": len(tool_runs_list),
            "unique_tools": len(by_tool),
            "status_counts": dict(status_counts),
            "tools": tools_summary,
        },
        "findings": {
            "total": len(findings_list),
            "by_tool": dict(findings_by_tool),
            "by_category": dict(findings_by_category),
            "mitre": {
                "total_mappings": int(mitre_total),
                "by_technique": dict(mitre_counts),
            },
        },
    }


def render_scan_report_md(
    *,
    scan: Mapping[str, Any],
    tool_runs: Iterable[Mapping[str, Any]],
    findings: Iterable[Mapping[str, Any]],
    max_findings: int = 50,
    max_finding_chars: int = 5000,
) -> str:
    tool_runs_list = [dict(r) for r in tool_runs]
    findings_list = [dict(f) for f in findings]

    summary = compute_scan_summary(scan=scan, tool_runs=tool_runs_list, findings=findings_list)

    scan_row = summary["scan"]
    tl = summary["timeline"]

    lines: list[str] = []
    lines.append("# Scan Report")
    lines.append("")
    lines.append(f"- **Scan ID**: `{scan_row.get('id')}`")
    lines.append(f"- **Target**: `{scan_row.get('target')}`")
    lines.append(f"- **Status**: `{scan_row.get('status')}`")
    if scan_row.get("triggered_by") is not None:
        lines.append(f"- **Triggered by**: `{scan_row.get('triggered_by')}`")
    if scan_row.get("api_key_id") is not None:
        lines.append(f"- **API key id**: `{scan_row.get('api_key_id')}`")
    if scan_row.get("concurrency_cap") is not None:
        lines.append(f"- **Concurrency cap**: `{scan_row.get('concurrency_cap')}`")
    lines.append(f"- **Created at**: `{_iso(scan_row.get('created_at'))}`")
    lines.append(f"- **First queued**: `{_iso(tl.get('first_queued_at'))}`")
    lines.append(f"- **First started**: `{_iso(tl.get('first_started_at'))}`")
    lines.append(f"- **Last finished**: `{_iso(tl.get('last_finished_at'))}`")
    lines.append(f"- **Duration (ms)**: `{tl.get('duration_ms')}`")

    live_targets = _extract_httpx_live_targets(findings_list, limit=50)
    lines.append("")
    lines.append("## Live Targets")
    lines.append("")
    if not live_targets:
        lines.append("_No live targets recorded (httpx not run or produced no results)._")
    else:
        lines.append(f"- **Count**: `{len(live_targets)}`")
        lines.append("")
        for u in live_targets:
            lines.append(f"- `{u}`")

    endpoints, endpoints_total, endpoints_truncated = _extract_katana_endpoints(findings_list, limit=100)
    lines.append("")
    lines.append("## Discovered Endpoints")
    lines.append("")
    if not endpoints:
        lines.append("_No endpoints recorded (katana not run or produced no URLs)._")
    else:
        shown = len(endpoints)
        if endpoints_total is not None:
            lines.append(f"- **Total discovered**: `{endpoints_total}`")
        lines.append(f"- **Shown**: `{shown}`")
        if endpoints_truncated is True:
            lines.append("- _Note: endpoint list is truncated for report size._")
        lines.append("")
        for u in endpoints:
            lines.append(f"- `{u}`")

    vulns, vulns_by_sev = _extract_nuclei_vulnerabilities(findings_list, limit=50)
    lines.append("")
    lines.append("## Vulnerabilities")
    lines.append("")
    if not vulns:
        lines.append("_No nuclei vulnerabilities recorded._")
    else:
        lines.append(f"- **Total**: `{sum(vulns_by_sev.values())}`")
        lines.append(f"- **By severity**: `{dict(vulns_by_sev)}`")
        lines.append("")
        lines.append("| Severity | Title | Matched At | Template |")
        lines.append("|---|---|---|---|")
        for v in vulns:
            sev = str(v.get("severity") or "unknown")
            title = str(v.get("title") or "")
            matched_at = str(v.get("matched_at") or "")
            template_id = str(v.get("template_id") or "")
            lines.append(f"| {sev} | {title} | {matched_at} | {template_id} |")

    lines.append("")
    lines.append("## Tool Runs")
    lines.append("")

    lines.append("| Tool | Status | Attempt | Duration (ms) | Exit | Error | Artifacts |")
    lines.append("|---|---:|---:|---:|---:|---|---|")

    def _fmt(v: Any) -> str:
        if v is None:
            return ""
        return str(v)

    for r in sorted(tool_runs_list, key=lambda rr: (rr.get("queued_at") or datetime.min, rr.get("tool") or "", int(rr.get("attempt") or 0))):
        lines.append(
            "| "
            + " | ".join(
                [
                    _fmt(r.get("tool")),
                    _fmt(r.get("status")),
                    _fmt(r.get("attempt")),
                    _fmt(r.get("duration_ms")),
                    _fmt(r.get("exit_code")),
                    _fmt(r.get("short_error")),
                    _fmt(r.get("artifact_path")),
                ]
            )
            + " |"
        )

    lines.append("")
    lines.append("## Artifacts")
    lines.append("")
    lines.append("| Tool | Attempt | Status | Artifact Path | Stdout | Stderr |")
    lines.append("|---|---:|---:|---|---|---|")

    for r in sorted(
        tool_runs_list,
        key=lambda rr: (
            rr.get("queued_at") or datetime.min,
            rr.get("tool") or "",
            int(rr.get("attempt") or 0),
        ),
    ):
        lines.append(
            "| "
            + " | ".join(
                [
                    _fmt(r.get("tool")),
                    _fmt(r.get("attempt")),
                    _fmt(r.get("status")),
                    _fmt(r.get("artifact_path")),
                    _fmt(r.get("stdout_path")),
                    _fmt(r.get("stderr_path")),
                ]
            )
            + " |"
        )

    lines.append("")
    lines.append("## Findings")
    lines.append("")
    lines.append(f"- **Total**: `{summary['findings']['total']}`")
    lines.append(f"- **By category**: `{summary['findings']['by_category']}`")
    lines.append("")

    shown = 0
    for f in findings_list[:max_findings]:
        shown += 1
        tool = str(f.get("tool") or "unknown")
        created_at = _iso(f.get("created_at"))
        payload = f.get("payload")
        mitre = f.get("mitre")

        lines.append(f"### {tool}")
        if created_at:
            lines.append("")
            lines.append(f"- **Created at**: `{created_at}`")

        if isinstance(mitre, list) and mitre:
            lines.append(f"- **MITRE ATT&CK**: `{len(mitre)}` technique(s)")
            for m in mitre:
                if not isinstance(m, dict):
                    continue
                tid = str(m.get("technique_id") or "").strip()
                if not tid:
                    continue
                name = str(m.get("name") or "").strip()
                tactic = str(m.get("tactic") or "").strip()
                tactics = m.get("tactics")
                conf = m.get("confidence")
                reason = str(m.get("reason") or "").strip()

                tactic_label = ""
                if isinstance(tactics, list) and tactics:
                    shortnames: list[str] = []
                    for t in tactics:
                        if not isinstance(t, dict):
                            continue
                        sn = str(t.get("shortname") or "").strip()
                        if sn:
                            shortnames.append(sn)
                    if shortnames:
                        tactic_label = ", ".join(sorted(set(shortnames)))
                elif tactic:
                    tactic_label = tactic

                label = tid
                if name:
                    label += f" {name}"
                if tactic_label:
                    label += f" ({tactic_label})"

                suffix_parts: list[str] = []
                if conf is not None:
                    try:
                        suffix_parts.append(f"confidence={float(conf):.2f}")
                    except Exception:
                        suffix_parts.append(f"confidence={conf}")
                if reason:
                    suffix_parts.append(reason)
                suffix = (" — " + "; ".join(suffix_parts)) if suffix_parts else ""
                lines.append(f"- `{label}`{suffix}")
        lines.append("")

        try:
            rendered = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
        except Exception:
            rendered = json.dumps({"payload": str(payload)}, indent=2, sort_keys=True, ensure_ascii=False)

        if len(rendered) > max_finding_chars:
            rendered = rendered[:max_finding_chars] + "\n... (truncated)"

        lines.append("```json")
        lines.append(rendered)
        lines.append("```")
        lines.append("")

    remaining = len(findings_list) - shown
    if remaining > 0:
        lines.append(f"_Omitted {remaining} additional findings (limit={max_findings})._")
        lines.append("")

    return "\n".join(lines)
