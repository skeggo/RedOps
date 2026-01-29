from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.parse import urldefrag

NAME = "ffuf"


def can_run(ctx: dict[str, Any]) -> bool:
    # Optional step: requires a live base URL.
    return bool(ctx.get("urls"))


def _load_fallback_words() -> list[str]:
    # Stored in the worker image at /app/wordlists/ffuf_fallback.txt
    # (__file__ is /app/tools/ffuf.py).
    path = Path(__file__).resolve().parents[1] / "wordlists" / "ffuf_fallback.txt"
    try:
        raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return ["admin", "login", "api", "graphql", "swagger", "docs", "robots.txt", "sitemap.xml"]

    out: list[str] = []
    for line in raw:
        line = (line or "").strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)

    if not out:
        return ["admin", "login", "api", "graphql", "swagger", "docs", "robots.txt", "sitemap.xml"]
    return out


def _top_dirs_from_urls(urls: list[str], *, max_dirs: int = 200) -> list[str]:
    c: Counter[str] = Counter()
    for u in urls:
        try:
            p = urlparse(u)
        except Exception:
            continue
        path = p.path or ""
        if not path or path == "/":
            continue
        parts = [seg for seg in path.split("/") if seg]
        if not parts:
            continue
        # Use top-level directory only (stable and small).
        c[parts[0]] += 1

    out: list[str] = []
    for d, _n in c.most_common():
        if d not in out:
            out.append(d)
        if len(out) >= max_dirs:
            break
    return out


def run(ctx: dict[str, Any], *, timeout: int, args: dict[str, Any] | None = None) -> dict[str, Any]:
    args = args or {}
    runner = ctx["run"]

    base_url = str((ctx.get("urls") or [""])[0]).rstrip("/")
    katana_urls: list[str] = [str(u) for u in (ctx.get("katana_urls") or []) if str(u).strip()]

    artifact_path = ctx.get("artifact_path")
    if not artifact_path:
        artifact_path = "/tmp/ffuf.json"

    wordlist_path = str(Path(str(artifact_path)).with_name("ffuf_wordlist.txt"))

    # Build a small deterministic wordlist from katana output + a tiny fallback set.
    dirs = _top_dirs_from_urls(katana_urls, max_dirs=int(args.get("max_dirs", 200)))
    fallback = _load_fallback_words()

    words: list[str] = []
    seen: set[str] = set()
    for w in dirs + fallback:
        w = (w or "").strip().lstrip("/")
        if not w or w in seen:
            continue
        seen.add(w)
        words.append(w)

    with open(wordlist_path, "w", encoding="utf-8", errors="replace") as f:
        for w in words:
            f.write(w + "\n")

    threads = int(args.get("threads", 20))
    req_timeout = int(args.get("req_timeout", 5))

    cmd = [
        "ffuf",
        "-u",
        f"{base_url}/FUZZ",
        "-w",
        wordlist_path,
        "-o",
        str(artifact_path),
        "-of",
        "json",
        "-t",
        str(threads),
        "-timeout",
        str(req_timeout),
    ]

    # ffuf writes to file; stdout is mostly progress.
    runner(cmd, timeout=timeout)

    hits: list[dict[str, Any]] = []
    try:
        with open(str(artifact_path), "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f) or {}
        hits = list(data.get("results") or [])
    except Exception:
        hits = []

    allowed_status = {200, 204, 301, 302, 401, 403}
    # For downstream scanning, redirects tend to be noisy (login redirects, canonicalization, etc.).
    include_redirects_downstream = bool(args.get("include_redirects_downstream", False))
    allowed_status_downstream = {200, 204, 401, 403} | ({301, 302} if include_redirects_downstream else set())
    max_urls_for_nuclei = int(args.get("max_urls_for_nuclei", 500))

    def _normalize_url(u: str) -> str | None:
        u = (u or "").strip()
        if not u:
            return None
        if not (u.startswith("http://") or u.startswith("https://")):
            return None
        u, _frag = urldefrag(u)
        # Strip trailing slash for stability (except root).
        if u.endswith("/") and len(u) > len("http://x/"):
            u = u.rstrip("/")
        return u

    # Provide ffuf-discovered URLs to downstream tools (e.g. nuclei): de-dupe + cap.
    ffuf_urls: list[str] = []
    seen_urls: set[str] = set()
    truncated = False
    for h in hits:
        try:
            status = int(h.get("status"))
        except Exception:
            continue
        if status not in allowed_status_downstream:
            continue
        nu = _normalize_url(str(h.get("url") or ""))
        if not nu or nu in seen_urls:
            continue
        seen_urls.add(nu)
        ffuf_urls.append(nu)
        if len(ffuf_urls) >= max(0, max_urls_for_nuclei):
            truncated = True
            break
    ctx["ffuf_urls"] = ffuf_urls

    inserted = 0
    insert_finding = ctx.get("insert_finding")
    scan_id = str(ctx.get("scan_id") or "")
    tool_run_id = ctx.get("tool_run_id")
    attempt = ctx.get("tool_attempt")

    if callable(insert_finding) and scan_id and tool_run_id:
        for h in hits:
            try:
                status = int(h.get("status"))
            except Exception:
                continue
            if status not in allowed_status:
                continue

            sev = "low"
            if status in {200, 204}:
                sev = "medium"

            payload = {
                "tool_run_id": tool_run_id,
                "attempt": attempt,
                "severity": sev,
                "title": "ffuf discovery",
                "url": h.get("url"),
                "status": status,
                "length": h.get("length"),
                "words": h.get("words"),
                "lines": h.get("lines"),
                "position": h.get("position"),
                "raw": h,
            }
            try:
                insert_finding(scan_id, "ffuf", payload)
                inserted += 1
            except Exception:
                pass

    return {
        "word_count": len(words),
        "hit_count": len(hits),
        "ffuf_url_count": len(ffuf_urls),
        "ffuf_urls_truncated": truncated,
        "max_urls_for_nuclei": max_urls_for_nuclei,
        "include_redirects_downstream": include_redirects_downstream,
        "inserted_findings": inserted,
    }
