from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str


# Minimal v1 catalog. Expand later as you add more rules.
TECHNIQUE_CATALOG: dict[str, MitreTechnique] = {
    "T1190": MitreTechnique("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "T1059": MitreTechnique("T1059", "Command and Scripting Interpreter", "Execution"),
    "T1203": MitreTechnique("T1203", "Exploitation for Client Execution", "Execution"),
    "T1552": MitreTechnique("T1552", "Unsecured Credentials", "Credential Access"),
}


_RE_SQLI = re.compile(r"\b(sql\s*injection|sqli|blind\s+sql|union\s+select)\b", re.IGNORECASE)
_RE_RCE = re.compile(r"\b(remote\s+code\s+execution|\brce\b|code\s+execution)\b", re.IGNORECASE)
_RE_CMD_INJECTION = re.compile(r"\b(command\s+injection|os\s+command\s+injection|shell\s+injection|cmd\s+injection)\b", re.IGNORECASE)
_RE_EXPOSED_LOGIN = re.compile(r"\b(admin\s+panel|admin\b|login\b|sign\s*in\b|wp-login|wp-admin|phpmyadmin)\b", re.IGNORECASE)

_RE_SECRET_MARKERS = re.compile(
    r"\b(secret|password|passwd|credential|api\s*key|token|private\s*key|ssh-rsa|authorization\s*:\s*bearer)\b",
    re.IGNORECASE,
)
_RE_SECRET_CONTEXT = re.compile(r"\b(exposed|leak|leaked|hardcoded|hard-coded|in\s+config|config\b)\b", re.IGNORECASE)


def _blob(payload: dict[str, Any], tool: str) -> str:
    parts: list[str] = [str(tool or "")]  # include tool name as context
    for k in (
        "title",
        "name",
        "template_id",
        "template-id",
        "normalized_title",
        "location",
        "normalized_location",
        "evidence",
        "key_evidence",
        "matcher_name",
        "matcher-name",
        "matched_at",
        "matched-at",
        "url",
        "host",
    ):
        v = payload.get(k)
        if v is None:
            continue
        try:
            s = str(v)
        except Exception:
            continue
        if s:
            parts.append(s)
    return "\n".join(parts)


def _add_best(existing: dict[str, dict[str, Any]], *, technique_id: str, confidence: float, reason: str) -> None:
    prev = existing.get(technique_id)
    if prev and float(prev.get("confidence") or 0.0) >= confidence:
        return
    existing[technique_id] = {
        "technique_id": technique_id,
        "confidence": float(confidence),
        "reason": str(reason),
        "source": "rules",
    }


def map_finding_to_mitre(*, tool: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Return MITRE technique mappings for a finding.

    Rules-based v1: deterministic string/regex matches.
    """

    t = (tool or "").strip().lower()
    p = dict(payload or {})
    b = _blob(p, tool=t)

    out: dict[str, dict[str, Any]] = {}

    # SQL injection -> T1190
    if _RE_SQLI.search(b):
        _add_best(
            out,
            technique_id="T1190",
            confidence=0.9,
            reason="SQL injection implies exploitation of a public-facing application surface.",
        )

    # Admin/login exposure (attack surface) -> T1190 (per project v1 mapping)
    if _RE_EXPOSED_LOGIN.search(b):
        _add_best(
            out,
            technique_id="T1190",
            confidence=0.6,
            reason="Exposed admin/login surface is a common initial access vector for public-facing apps.",
        )

    # Command injection -> T1059
    if _RE_CMD_INJECTION.search(b):
        _add_best(
            out,
            technique_id="T1059",
            confidence=0.85,
            reason="Command injection typically results in command interpreter execution.",
        )
    # Generic RCE -> T1203 (taxonomy choice; can be refined later)
    elif _RE_RCE.search(b):
        _add_best(
            out,
            technique_id="T1203",
            confidence=0.75,
            reason="Remote code execution indicates exploitation leading to code execution.",
        )

    # Exposed secrets/credentials -> T1552
    if _RE_SECRET_MARKERS.search(b) and _RE_SECRET_CONTEXT.search(b):
        _add_best(
            out,
            technique_id="T1552",
            confidence=0.9,
            reason="Finding indicates exposed/unencrypted credentials or secrets.",
        )

    return sorted(out.values(), key=lambda x: (-float(x.get("confidence") or 0.0), str(x.get("technique_id") or "")))


def techniques_to_seed(technique_ids: Iterable[str]) -> list[MitreTechnique]:
    out: list[MitreTechnique] = []
    for tid in technique_ids:
        t = TECHNIQUE_CATALOG.get(str(tid))
        if t:
            out.append(t)
        else:
            out.append(MitreTechnique(str(tid), name="", tactic=""))
    # Stable order
    out_sorted = sorted(out, key=lambda x: x.technique_id)
    return out_sorted
