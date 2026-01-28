from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_WS_RE = re.compile(r"\s+")


def _collapse_ws(s: str) -> str:
    return _WS_RE.sub(" ", (s or "").strip())


def normalize_text(s: str | None) -> str:
    return _collapse_ws(s or "").lower()


def normalize_location(location: str | None) -> str:
    """Best-effort canonicalization for URLs/hosts/paths.

    Goal: stable strings for fingerprinting, not perfect URL normalization.
    """

    raw = str(location or "").strip()
    if not raw:
        return ""

    # Try URL normalization when it looks like a URL.
    looks_like_url = "://" in raw or raw.startswith("http://") or raw.startswith("https://")
    if not looks_like_url:
        return normalize_text(raw)

    try:
        parts = urlsplit(raw)
    except Exception:
        return normalize_text(raw)

    scheme = (parts.scheme or "").lower()
    netloc = (parts.netloc or "").lower()

    # Strip default ports.
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[: -len(":80")]
    if scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[: -len(":443")]

    path = parts.path or ""
    # Normalize duplicated slashes and trailing slash (except root).
    path = re.sub(r"/{2,}", "/", path)
    if path != "/" and path.endswith("/"):
        path = path[:-1]

    query = parts.query or ""
    if query:
        try:
            pairs = parse_qsl(query, keep_blank_values=True)
            query = urlencode(sorted(pairs))
        except Exception:
            # Leave query as-is if parsing fails.
            pass

    # Drop fragments.
    fragment = ""

    return urlunsplit((scheme, netloc, path, query, fragment))


def _pick_first(payload: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for k in keys:
        v = payload.get(k)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return None


def _stable_jsonish(obj: Any, *, limit: int = 4000) -> str:
    """Turn a small piece of evidence into a stable, bounded string."""

    if obj is None:
        return ""
    if isinstance(obj, (str, int, float, bool)):
        s = str(obj)
    elif isinstance(obj, list):
        # Lists are often order-noisy; sort stringified values.
        items = [str(x) for x in obj if x is not None]
        items = [x.strip() for x in items if x.strip()]
        s = "|".join(sorted(set(items)))
    elif isinstance(obj, dict):
        # Dicts: stable key order.
        parts: list[str] = []
        for k in sorted(obj.keys(), key=lambda x: str(x)):
            parts.append(f"{k}={_stable_jsonish(obj.get(k), limit=limit)}")
        s = "&".join(parts)
    else:
        s = str(obj)

    s = _collapse_ws(s)
    if len(s) > limit:
        s = s[:limit]
    return s


def normalize_finding(tool: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Enrich payload with consistent finding fields.

    We keep original tool-specific keys intact for backwards compatibility,
    and add standardized keys for reporting/deduping.
    """

    tool_str = str(tool or "").strip()
    p: dict[str, Any] = dict(payload or {})

    # Kind is helpful for downstream rendering.
    kind = "result"
    tl = tool_str.lower()
    if tl.endswith("_skipped"):
        kind = "skipped"
    elif tl.endswith("_timeout"):
        kind = "timeout"
    elif tl.endswith("_error") or tl in ("error",):
        kind = "error"

    title = _pick_first(p, ("title", "name", "template_id", "template-id"))
    if not title:
        if tool_str == "httpx":
            title = "httpx live targets"
        elif tool_str == "katana":
            title = "katana endpoints"
        else:
            title = tool_str or "finding"

    # Location: prefer tool-specific stable fields.
    location = _pick_first(
        p,
        (
            "location",
            "matched_at",
            "matched-at",
            "url",
            "host",
            "target",
            "scanned_url",
        ),
    )

    severity = _pick_first(p, ("severity",))
    if not severity:
        severity = "info" if kind in ("skipped", "timeout") else "unknown"

    # Key evidence: keep it stable and bounded.
    key_evidence = _pick_first(
        p,
        (
            "key_evidence",
            "template_id",
            "template-id",
            "matcher_name",
            "matcher-name",
            "extracted_results",
            "extracted-results",
            "status_code",
            "status-code",
            "error",
            "short_error",
        ),
    )

    # For tools that return big URL lists, derive stable evidence from a sorted sample.
    if tool_str in ("httpx", "katana") and not key_evidence:
        urls = p.get("urls")
        if not isinstance(urls, list):
            urls = None
        if tool_str == "httpx":
            results = p.get("results")
            if isinstance(results, list):
                extracted: list[str] = []
                for r in results:
                    if isinstance(r, dict) and r.get("url"):
                        extracted.append(str(r.get("url")))
                urls = urls or extracted

        if isinstance(urls, list):
            sample = [str(u).strip() for u in urls if str(u).strip()]
            sample = sorted(set(sample))[:50]
            key_evidence = "|".join(sample)

    evidence = p.get("evidence")
    if evidence is None:
        evidence = key_evidence

    # Normalized strings for fingerprinting.
    normalized_title = normalize_text(str(title))
    normalized_location = normalize_location(location)
    normalized_key_evidence = normalize_text(_stable_jsonish(key_evidence))

    p.setdefault("schema", "finding.v1")
    p["kind"] = kind
    p["title"] = title
    p["location"] = location
    p["severity"] = str(severity).strip().lower() if severity is not None else None
    p["evidence"] = evidence
    p["normalized_title"] = normalized_title
    p["normalized_location"] = normalized_location
    p["key_evidence"] = _stable_jsonish(key_evidence)

    return p


def compute_fingerprint(tool: str, payload: dict[str, Any]) -> str:
    tool_str = str(tool or "").strip().lower()
    title = normalize_text(str(payload.get("normalized_title") or payload.get("title") or ""))
    location = normalize_location(str(payload.get("normalized_location") or payload.get("location") or ""))
    key_evidence = normalize_text(str(payload.get("key_evidence") or payload.get("evidence") or ""))

    base = "\n".join([tool_str, title, location, key_evidence])
    return hashlib.sha256(base.encode("utf-8", errors="ignore")).hexdigest()


def normalize_and_fingerprint(tool: str, payload: dict[str, Any]) -> tuple[dict[str, Any], str]:
    normalized = normalize_finding(tool, payload)
    fp = compute_fingerprint(tool, normalized)
    normalized["fingerprint"] = fp
    return normalized, fp
