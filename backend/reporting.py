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

        lines.append(f"### {tool}")
        if created_at:
            lines.append("")
            lines.append(f"- **Created at**: `{created_at}`")
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
