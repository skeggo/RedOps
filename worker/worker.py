import os
import json
import time
import uuid
import subprocess
import shutil
import threading
from datetime import datetime
from urllib.parse import urlsplit
from typing import Iterable
from sqlalchemy import create_engine, text

import yaml

from tools.plugin import load_tool
from scope_controls import ScopeError, load_allowlist, validate_target
from common.normalizer import normalize_and_fingerprint
from common.mitre_rules import map_finding_to_mitre, techniques_to_seed

DATABASE_URL = os.environ["DATABASE_URL"]
engine = create_engine(DATABASE_URL, future=True)

FAST_MODE = os.getenv("FAST_MODE", "1") == "1"
PIPELINE = os.getenv("PIPELINE", "default")


def log(msg: str):
    print(f"[worker] {msg}", flush=True)


def init_db():
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS scans (
                  id TEXT PRIMARY KEY,
                  target TEXT NOT NULL,
                  api_key_id TEXT NULL,
                  triggered_by TEXT NOT NULL DEFAULT 'local',
                  triggered_via TEXT NOT NULL DEFAULT 'api',
                  request_ip INET NULL,
                  concurrency_cap INT NULL,
                  status TEXT NOT NULL,
                  created_at TIMESTAMP NOT NULL
                );
                """
            )
        )

        # Add new columns to existing installs (best-effort in-app migration).
        conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS api_key_id TEXT NULL"))
        conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS triggered_by TEXT NOT NULL DEFAULT 'local'"))
        conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS triggered_via TEXT NOT NULL DEFAULT 'api'"))
        conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS request_ip INET NULL"))
        conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS concurrency_cap INT NULL"))

        conn.execute(text("ALTER TABLE scans ALTER COLUMN triggered_by SET DEFAULT 'local'"))
        conn.execute(text("ALTER TABLE scans ALTER COLUMN triggered_via SET DEFAULT 'api'"))
        conn.execute(text("UPDATE scans SET triggered_by='local' WHERE triggered_by='unknown'"))
        conn.execute(text("UPDATE scans SET api_key_id=NULL WHERE api_key_id='unknown'"))

        conn.execute(
            text(
                """
                DO $$
                BEGIN
                    ALTER TABLE scans ALTER COLUMN api_key_id DROP NOT NULL;
                EXCEPTION WHEN others THEN
                    NULL;
                END $$;
                """
            )
        )
        conn.execute(
            text(
                """
                DO $$
                BEGIN
                    ALTER TABLE scans ALTER COLUMN api_key_id DROP DEFAULT;
                EXCEPTION WHEN others THEN
                    NULL;
                END $$;
                """
            )
        )

        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS findings (
                  id SERIAL PRIMARY KEY,
                  scan_id TEXT NOT NULL,
                  tool TEXT NOT NULL,
                  fingerprint TEXT NULL,
                  asset_id INT NULL,
                  endpoint_id INT NULL,
                  payload JSONB NOT NULL,
                  created_at TIMESTAMP NOT NULL
                );
                """
            )
        )

        # Best-effort migration for existing installs.
        conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint TEXT NULL"))
        conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS asset_id INT NULL"))
        conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS endpoint_id INT NULL"))

        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings (asset_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_findings_endpoint_id ON findings (endpoint_id)"))
        # Enforce dedupe for new rows (existing NULL fingerprints won't participate).
        conn.execute(
            text(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_scan_fingerprint_unique
                ON findings (scan_id, fingerprint)
                WHERE fingerprint IS NOT NULL
                """
            )
        )

        # Assets/endpoints tables (scan-scoped; minimal fields for reporting).
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS assets (
                  id SERIAL PRIMARY KEY,
                  scan_id TEXT NOT NULL,
                  host TEXT NOT NULL,
                  port INT NULL,
                  scheme TEXT NULL,
                  tech JSONB NULL,
                  headers_summary JSONB NULL,
                  discovered_at TIMESTAMP NOT NULL
                );
                """
            )
        )
        conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS tech JSONB NULL"))
        conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS headers_summary JSONB NULL"))
        conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS discovered_at TIMESTAMP NOT NULL DEFAULT now()"))

        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_assets_scan_id ON assets (scan_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_assets_host ON assets (host)"))
        conn.execute(
            text(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_scan_host_port_scheme_unique
                ON assets (scan_id, host, port, scheme)
                """
            )
        )

        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS endpoints (
                  id SERIAL PRIMARY KEY,
                  scan_id TEXT NOT NULL,
                  asset_id INT NULL,
                  url TEXT NOT NULL,
                  method TEXT NOT NULL DEFAULT '',
                  status INT NULL,
                  title TEXT NULL,
                  source TEXT NOT NULL,
                  discovered_at TIMESTAMP NOT NULL
                );
                """
            )
        )
        conn.execute(text("ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS discovered_at TIMESTAMP NOT NULL DEFAULT now()"))
        conn.execute(text("ALTER TABLE endpoints ALTER COLUMN method SET DEFAULT ''"))

        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_endpoints_scan_id ON endpoints (scan_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_endpoints_asset_id ON endpoints (asset_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_endpoints_url ON endpoints (url)"))
        conn.execute(
            text(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoints_scan_url_method_unique
                ON endpoints (scan_id, url, method)
                """
            )
        )

        # Best-effort in-app migration from the legacy MVP schema (tool_runs without `id`).
        conn.execute(
            text(
                """
                DO $$
                BEGIN
                    IF EXISTS (
                        SELECT 1
                        FROM information_schema.tables
                        WHERE table_schema='public' AND table_name='tool_runs'
                    ) THEN
                        IF NOT EXISTS (
                            SELECT 1
                            FROM information_schema.columns
                            WHERE table_schema='public' AND table_name='tool_runs' AND column_name='id'
                        ) THEN
                            IF NOT EXISTS (
                                SELECT 1
                                FROM information_schema.tables
                                WHERE table_schema='public' AND table_name='tool_runs_legacy'
                            ) THEN
                                ALTER TABLE public.tool_runs RENAME TO tool_runs_legacy;
                            END IF;
                        END IF;
                    END IF;
                END $$;
                """
            )
        )

        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS tool_runs (
                    id UUID PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempt INT NOT NULL,
                    queued_at TIMESTAMP NOT NULL,
                    started_at TIMESTAMP NULL,
                    finished_at TIMESTAMP NULL,
                    duration_ms BIGINT NULL,
                    exit_code INT NULL,
                    stdout_path TEXT NULL,
                    stderr_path TEXT NULL,
                    artifact_path TEXT NULL,
                    args JSONB NOT NULL DEFAULT '{}'::jsonb,
                    short_error TEXT NULL,
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    CONSTRAINT tool_runs_attempt_positive CHECK (attempt >= 1),
                    CONSTRAINT tool_runs_scan_tool_attempt_unique UNIQUE (scan_id, tool, attempt)
                );
                """
            )
        )

        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_tool_runs_scan_timeline ON tool_runs (scan_id, queued_at)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_tool_runs_scan_tool_attempt ON tool_runs (scan_id, tool, attempt)"))
        conn.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS idx_tool_runs_failed_recent
                ON tool_runs (finished_at DESC)
                WHERE status IN ('failed','timeout')
                """
            )
        )

        # MITRE ATT&CK mapping tables (rules-based v1)
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS mitre_techniques (
                  technique_id TEXT PRIMARY KEY,
                  name TEXT NULL,
                  tactic TEXT NULL
                );
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS finding_mitre (
                  finding_id INT NOT NULL,
                  technique_id TEXT NOT NULL,
                  confidence DOUBLE PRECISION NULL,
                  reason TEXT NULL,
                  source TEXT NOT NULL DEFAULT 'rules',
                  CONSTRAINT finding_mitre_finding_fk FOREIGN KEY (finding_id)
                    REFERENCES findings(id) ON DELETE CASCADE,
                  CONSTRAINT finding_mitre_technique_fk FOREIGN KEY (technique_id)
                    REFERENCES mitre_techniques(technique_id) ON DELETE RESTRICT,
                  CONSTRAINT finding_mitre_unique UNIQUE (finding_id, technique_id, source)
                );
                """
            )
        )
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_finding_mitre_finding_id ON finding_mitre (finding_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_finding_mitre_technique_id ON finding_mitre (technique_id)"))


def _ensure_mitre_techniques(conn, technique_ids: Iterable[str]) -> None:
    seeds = techniques_to_seed(technique_ids)
    if not seeds:
        return
    stmt = text(
        """
        INSERT INTO mitre_techniques (technique_id, name, tactic)
        VALUES (:id,:name,:tactic)
        ON CONFLICT (technique_id)
        DO UPDATE SET
          name = COALESCE(NULLIF(mitre_techniques.name, ''), EXCLUDED.name),
          tactic = COALESCE(NULLIF(mitre_techniques.tactic, ''), EXCLUDED.tactic)
        """
    )
    for t in seeds:
        conn.execute(stmt, {"id": t.technique_id, "name": t.name, "tactic": t.tactic})


def _apply_mitre_mapping(conn, *, finding_id: int, tool: str, payload: dict) -> None:
    mappings = map_finding_to_mitre(tool=tool, payload=payload)
    if not mappings:
        return

    technique_ids = [str(m.get("technique_id")) for m in mappings if m.get("technique_id")]
    _ensure_mitre_techniques(conn, technique_ids)

    stmt = text(
        """
        INSERT INTO finding_mitre (finding_id, technique_id, confidence, reason, source)
        VALUES (:finding_id,:technique_id,:confidence,:reason,:source)
        ON CONFLICT (finding_id, technique_id, source)
        DO UPDATE SET
          confidence = GREATEST(COALESCE(finding_mitre.confidence, 0), COALESCE(EXCLUDED.confidence, 0)),
          reason = COALESCE(EXCLUDED.reason, finding_mitre.reason)
        """
    )
    for m in mappings:
        conn.execute(
            stmt,
            {
                "finding_id": int(finding_id),
                "technique_id": str(m.get("technique_id")),
                "confidence": float(m.get("confidence")) if m.get("confidence") is not None else None,
                "reason": str(m.get("reason")) if m.get("reason") is not None else None,
                "source": str(m.get("source") or "rules"),
            },
        )


def _tail(s: str | None, n: int) -> str | None:
    if not s:
        return None
    return s[-n:]


def _utcnow() -> datetime:
    return datetime.utcnow()


def _duration_ms(started_at: datetime | None, finished_at: datetime | None) -> int | None:
    if not started_at or not finished_at:
        return None
    return int((finished_at - started_at).total_seconds() * 1000)


def _scrub(obj):
    """Sanitize args/metadata: redact common secret-ish keys; ensure JSON-serializable."""
    if obj is None:
        return None
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            key = str(k)
            lowered = key.lower()
            if any(tok in lowered for tok in ["password", "passwd", "secret", "token", "apikey", "api_key", "key"]):
                out[key] = "***"
            else:
                out[key] = _scrub(v)
        return out
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)):
        return obj
    return str(obj)


def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


TOOL_RUNS_DIR = os.getenv("TOOL_RUNS_DIR", "/tmp/tool_runs")
ARTIFACTS_DIR = os.getenv("ARTIFACTS_DIR", "/tmp/artifacts")


PRIMARY_ARTIFACT_NAMES: dict[str, str] = {
    "httpx": "httpx.jsonl",
    "katana": "katana_urls.txt",
    "nuclei": "nuclei.jsonl",
    "ffuf": "ffuf.json",
}


TOOL_ARTIFACTS: dict[str, list[str]] = {
    # Best-effort copies of common temp outputs into the per-run artifact dir.
    "nikto": ["/tmp/nikto.json"],
    "nuclei": ["/tmp/targets.txt"],
}


class ToolRunRecorder:
    def __init__(self, stdout_path: str | None = None, stderr_path: str | None = None):
        self.exit_code: int | None = 0
        self.stderr_tail: str | None = None
        self.timed_out: bool = False
        self.stdout_path = stdout_path
        self.stderr_path = stderr_path
        # Optional context for live DB progress updates.
        self.run_id: str | None = None
        self.tool: str | None = None
        self._last_progress_percent: float | None = None
        self._last_progress_update_ts: float = 0.0

    def append(self, stdout: str | None, stderr: str | None):
        if self.stdout_path and stdout:
            with open(self.stdout_path, "a", encoding="utf-8", errors="replace") as f:
                f.write(stdout)
                if not stdout.endswith("\n"):
                    f.write("\n")
        if self.stderr_path and stderr:
            with open(self.stderr_path, "a", encoding="utf-8", errors="replace") as f:
                f.write(stderr)
                if not stderr.endswith("\n"):
                    f.write("\n")

    def observe(self, exit_code: int, stdout: str | None, stderr: str | None):
        if exit_code != 0:
            self.exit_code = exit_code
        if stderr:
            self.stderr_tail = _tail(stderr, 2000)
        self.append(stdout, stderr)

    def observe_timeout(self, stderr: str | None = None):
        self.timed_out = True
        self.exit_code = None
        if stderr:
            self.stderr_tail = _tail(stderr, 2000)
            # Persist stderr so timeouts still leave useful diagnostics on disk.
            self.append(None, stderr)


def create_tool_run(
    *,
    scan_id: str,
    tool: str,
    status: str,
    queued_at: datetime,
    stdout_path: str | None,
    stderr_path: str | None,
    artifact_path: str | None,
    args: dict,
    short_error: str | None,
    metadata: dict,
) -> tuple[str, int]:
    run_id = str(uuid.uuid4())
    with engine.begin() as conn:
        row = conn.execute(
            text(
                """
                INSERT INTO tool_runs (
                  id, scan_id, tool, status, attempt, queued_at,
                  stdout_path, stderr_path, artifact_path,
                  args, short_error, metadata
                )
                VALUES (
                  :id, :scan_id, :tool, :status,
                  (SELECT COALESCE(MAX(attempt), 0) + 1 FROM tool_runs WHERE scan_id=:scan_id AND tool=:tool),
                  :queued_at,
                  :stdout_path, :stderr_path, :artifact_path,
                                    CAST(:args AS JSONB), :short_error, CAST(:metadata AS JSONB)
                )
                RETURNING id::text AS id, attempt
                """
            ),
            {
                "id": run_id,
                "scan_id": scan_id,
                "tool": tool,
                "status": status,
                "queued_at": queued_at,
                "stdout_path": stdout_path,
                "stderr_path": stderr_path,
                "artifact_path": artifact_path,
                "args": json.dumps(_scrub(args) or {}),
                "short_error": short_error,
                "metadata": json.dumps(_scrub(metadata) or {}),
            },
        ).mappings().first()
    return str(row["id"]), int(row["attempt"])


def update_tool_run(
    *,
    run_id: str,
    status: str,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    duration_ms: int | None = None,
    exit_code: int | None = None,
    short_error: str | None = None,
):
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                UPDATE tool_runs
                SET
                  status = :status,
                  started_at = COALESCE(started_at, :started_at),
                  finished_at = :finished_at,
                  duration_ms = :duration_ms,
                  exit_code = :exit_code,
                  short_error = :short_error
                WHERE id = :id
                """
            ),
            {
                "id": run_id,
                "status": status,
                "started_at": started_at,
                "finished_at": finished_at,
                "duration_ms": duration_ms,
                "exit_code": exit_code,
                "short_error": short_error,
            },
        )


def update_tool_run_metadata(*, run_id: str, patch: dict):
    """Merge a JSON patch into tool_runs.metadata for a single run.

    Used for live progress updates (e.g., nuclei -stats percent).
    """

    if not patch:
        return
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                UPDATE tool_runs
                SET metadata = metadata || CAST(:patch AS JSONB)
                WHERE id = :id
                """
            ),
            {"id": run_id, "patch": json.dumps(_scrub(patch) or {})},
        )


def _parse_nuclei_stats_line(line: str) -> dict | None:
    s = (line or "").strip()
    if not s or not s.startswith("{"):
        return None
    try:
        obj = json.loads(s)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    if "percent" not in obj:
        return None

    # Normalize percent to a float if possible.
    p = obj.get("percent")
    percent: float | None
    try:
        if isinstance(p, str):
            p = p.strip().rstrip("%")
        percent = float(p)
    except Exception:
        percent = None

    out: dict = {"raw": obj}
    if percent is not None:
        out["percent"] = max(0.0, min(100.0, percent))

    # Copy a few commonly useful fields when present.
    for key in ("duration", "errors", "hosts", "matched", "requests", "templates", "total"):
        if key in obj:
            out[key] = obj.get(key)
    return out


def run(cmd: list[str], timeout: int = 600, recorder: ToolRunRecorder | None = None) -> str:
    log("CMD: " + " ".join(cmd))

    # Stream output into recorder files so long-running tools (e.g. nuclei -stats)
    # can be tailed while running.
    MAX_CAPTURE_CHARS = 5_000_000  # bound memory while still enabling parsing for most tools
    stdout_parts: list[str] = []
    captured_chars = 0
    stderr_tail = ""
    stderr_lock = threading.Lock()

    def _read_stream(stream, *, is_stdout: bool):
        nonlocal captured_chars, stderr_tail
        try:
            for line in iter(stream.readline, ""):
                if recorder:
                    recorder.append(line if is_stdout else None, None if is_stdout else line)
                if is_stdout and captured_chars < MAX_CAPTURE_CHARS:
                    stdout_parts.append(line)
                    captured_chars += len(line)
                if not is_stdout:
                    with stderr_lock:
                        stderr_tail = (stderr_tail + line)[-2000:]

                    # Live progress for nuclei (-stats emits JSON lines on stderr).
                    if recorder and recorder.tool == "nuclei" and recorder.run_id:
                        stats = _parse_nuclei_stats_line(line)
                        if stats and "percent" in stats:
                            now = time.monotonic()
                            percent = float(stats.get("percent"))
                            should_write = False
                            if recorder._last_progress_percent is None:
                                should_write = True
                            elif abs(percent - float(recorder._last_progress_percent)) >= 1.0:
                                should_write = True
                            elif (now - float(recorder._last_progress_update_ts or 0.0)) >= 2.0:
                                should_write = True

                            if should_write:
                                recorder._last_progress_percent = percent
                                recorder._last_progress_update_ts = now
                                update_tool_run_metadata(
                                    run_id=recorder.run_id,
                                    patch={
                                        "progress": {"tool": "nuclei", "percent": percent},
                                        "nuclei_stats": stats,
                                    },
                                )
        finally:
            try:
                stream.close()
            except Exception:
                pass

    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    t_out = threading.Thread(target=_read_stream, args=(p.stdout,), kwargs={"is_stdout": True}, daemon=True)
    t_err = threading.Thread(target=_read_stream, args=(p.stderr,), kwargs={"is_stdout": False}, daemon=True)
    t_out.start()
    t_err.start()

    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired as e:
        try:
            p.kill()
        except Exception:
            pass
        with stderr_lock:
            tail = stderr_tail
        if recorder:
            recorder.observe_timeout(stderr=tail or str(e))
        raise
    finally:
        # Best-effort drain.
        t_out.join(timeout=1)
        t_err.join(timeout=1)

    exit_code = int(p.returncode or 0)
    if recorder:
        recorder.exit_code = exit_code
        with stderr_lock:
            recorder.stderr_tail = stderr_tail or None

    if exit_code != 0:
        with stderr_lock:
            log("STDERR: " + (_tail(stderr_tail, 500) or ""))

    return ("".join(stdout_parts) or "").strip()


def _url_to_asset_parts(url: str) -> tuple[str | None, str | None, int | None]:
    """Return (scheme, host, port) for a URL-like string."""
    u = (url or "").strip()
    if not u:
        return None, None, None

    # Allow raw host:port in a pinch.
    if "://" not in u and ("/" not in u) and (":" in u):
        u = "http://" + u

    try:
        parts = urlsplit(u)
    except Exception:
        return None, None, None

    scheme = (parts.scheme or "").lower() or None
    host = (parts.hostname or "").strip().lower() or None
    port = parts.port

    if port is None and scheme in ("http", "https"):
        port = 80 if scheme == "http" else 443

    return scheme, host, port


def _summarize_headers(headers: object) -> dict | None:
    if not isinstance(headers, dict):
        return None
    out: dict[str, str] = {}
    for k in ["server", "content-type", "x-powered-by", "strict-transport-security", "location"]:
        for kk in (k, k.title(), k.upper()):
            if kk in headers and headers.get(kk) is not None:
                out[k] = str(headers.get(kk))
                break
    return out or None


def _upsert_asset(
    conn,
    *,
    scan_id: str,
    host: str,
    port: int | None,
    scheme: str | None,
    tech: dict | None,
    headers_summary: dict | None,
) -> int | None:
    if not scan_id or not host:
        return None
    row = conn.execute(
        text(
            """
            INSERT INTO assets (scan_id, host, port, scheme, tech, headers_summary, discovered_at)
            VALUES (:scan_id, :host, :port, :scheme, CAST(:tech AS JSONB), CAST(:headers AS JSONB), :c)
            ON CONFLICT (scan_id, host, port, scheme)
            DO UPDATE SET
              tech = COALESCE(EXCLUDED.tech, assets.tech),
              headers_summary = COALESCE(EXCLUDED.headers_summary, assets.headers_summary)
            RETURNING id
            """
        ),
        {
            "scan_id": scan_id,
            "host": host,
            "port": port,
            "scheme": scheme,
            "tech": json.dumps(tech) if tech is not None else None,
            "headers": json.dumps(headers_summary) if headers_summary is not None else None,
            "c": datetime.utcnow(),
        },
    ).mappings().first()
    try:
        return int(row["id"]) if row else None
    except Exception:
        return None


def _upsert_endpoint(
    conn,
    *,
    scan_id: str,
    asset_id: int | None,
    url: str,
    method: str | None,
    status: int | None,
    title: str | None,
    source: str,
) -> int | None:
    if not scan_id or not url or not source:
        return None
    m = (method or "").strip().upper()
    row = conn.execute(
        text(
            """
            INSERT INTO endpoints (scan_id, asset_id, url, method, status, title, source, discovered_at)
            VALUES (:scan_id, :asset_id, :url, :method, :status, :title, :source, :c)
            ON CONFLICT (scan_id, url, method)
            DO UPDATE SET
              asset_id = COALESCE(endpoints.asset_id, EXCLUDED.asset_id),
              status = COALESCE(EXCLUDED.status, endpoints.status),
              title = COALESCE(EXCLUDED.title, endpoints.title)
            RETURNING id
            """
        ),
        {
            "scan_id": scan_id,
            "asset_id": asset_id,
            "url": str(url),
            "method": m,
            "status": status,
            "title": title,
            "source": str(source),
            "c": datetime.utcnow(),
        },
    ).mappings().first()
    try:
        return int(row["id"]) if row else None
    except Exception:
        return None


def _derive_ids_for_finding(conn, *, scan_id: str, tool: str, payload: dict) -> tuple[int | None, int | None]:
    t = (tool or "").strip().lower()

    # Summary tools that include many URLs/results: populate tables, but don't force a single id.
    if t == "httpx":
        results = payload.get("results")
        if isinstance(results, list):
            for r in results:
                if not isinstance(r, dict):
                    continue
                u = str(r.get("url") or "").strip()
                scheme, host, port = _url_to_asset_parts(u)
                if not host:
                    continue

                tech: dict | None = None
                try:
                    tech = {
                        "webserver": r.get("webserver"),
                        "technologies": r.get("technologies") or r.get("tech"),
                        "cdn": r.get("cdn"),
                    }
                except Exception:
                    tech = None
                tech = tech or None

                headers_summary = _summarize_headers(r.get("header") or r.get("headers"))
                asset_id = _upsert_asset(conn, scan_id=scan_id, host=host, port=port, scheme=scheme, tech=tech, headers_summary=headers_summary)
                if u:
                    _upsert_endpoint(
                        conn,
                        scan_id=scan_id,
                        asset_id=asset_id,
                        url=u,
                        method=None,
                        status=int(r.get("status_code")) if r.get("status_code") is not None else None,
                        title=str(r.get("title") or "").strip() or None,
                        source="httpx",
                    )
        return None, None

    if t == "katana":
        urls = payload.get("urls")
        if isinstance(urls, list):
            for u0 in urls:
                u = str(u0 or "").strip()
                scheme, host, port = _url_to_asset_parts(u)
                if not host:
                    continue
                asset_id = _upsert_asset(conn, scan_id=scan_id, host=host, port=port, scheme=scheme, tech=None, headers_summary=None)
                _upsert_endpoint(conn, scan_id=scan_id, asset_id=asset_id, url=u, method=None, status=None, title=None, source="katana")
        return None, None

    # Per-endpoint tools.
    url = str(payload.get("url") or payload.get("matched_at") or payload.get("matched-at") or payload.get("host") or "").strip()
    if not url:
        return None, None

    scheme, host, port = _url_to_asset_parts(url)
    if not host:
        return None, None

    asset_id = _upsert_asset(conn, scan_id=scan_id, host=host, port=port, scheme=scheme, tech=None, headers_summary=None)

    source = "unknown"
    if t.startswith("ffuf"):
        source = "ffuf"
    elif t.startswith("nuclei"):
        source = "nuclei"
    elif t.startswith("nikto"):
        source = "nikto"
    elif t.startswith("httpx"):
        source = "httpx"
    elif t.startswith("katana"):
        source = "katana"
    else:
        source = t or "unknown"

    status = None
    try:
        if payload.get("status") is not None:
            status = int(payload.get("status"))
        elif payload.get("status_code") is not None:
            status = int(payload.get("status_code"))
    except Exception:
        status = None

    title = str(payload.get("endpoint_title") or payload.get("title") or "").strip() or None
    method = payload.get("method")
    endpoint_id = _upsert_endpoint(conn, scan_id=scan_id, asset_id=asset_id, url=url, method=str(method) if method else None, status=status, title=title, source=source)
    return asset_id, endpoint_id


def insert_finding(scan_id: str, tool: str, payload: dict) -> bool:
    normalized_payload, fingerprint = normalize_and_fingerprint(tool, payload)
    with engine.begin() as conn:
        asset_id, endpoint_id = _derive_ids_for_finding(conn, scan_id=scan_id, tool=tool, payload=normalized_payload)
        res = conn.execute(
            text(
                """
                INSERT INTO findings (scan_id, tool, fingerprint, asset_id, endpoint_id, payload, created_at)
                VALUES (:id,:tool,:fp,:asset_id,:endpoint_id,:p,:c)
                ON CONFLICT (scan_id, fingerprint)
                WHERE fingerprint IS NOT NULL
                DO NOTHING
                RETURNING id
                """
            ),
            {
                "id": scan_id,
                "tool": tool,
                "fp": fingerprint,
                "asset_id": asset_id,
                "endpoint_id": endpoint_id,
                "p": json.dumps(normalized_payload),
                "c": datetime.utcnow(),
            },
        )
        finding_row = None
        try:
            finding_row = res.mappings().first()
        except Exception:
            finding_row = None
        if finding_row and finding_row.get("id") is not None:
            _apply_mitre_mapping(conn, finding_id=int(finding_row["id"]), tool=tool, payload=normalized_payload)
    try:
        return bool(res.rowcount)
    except Exception:
        return True


def insert_findings_bulk(scan_id: str, tool: str, payloads: list[dict]) -> int:
    """Insert many findings in a single transaction.

    This is primarily to keep high-volume tools (e.g. nuclei) from spending most
    of their runtime on per-row transaction overhead.
    """

    if not payloads:
        return 0

    inserted = 0
    now = datetime.utcnow()
    with engine.begin() as conn:
        stmt = text(
            """
            INSERT INTO findings (scan_id, tool, fingerprint, asset_id, endpoint_id, payload, created_at)
            VALUES (:id,:tool,:fp,:asset_id,:endpoint_id,:p,:c)
            ON CONFLICT (scan_id, fingerprint)
            WHERE fingerprint IS NOT NULL
            DO NOTHING
            RETURNING id
            """
        )

        for payload in payloads:
            normalized_payload, fingerprint = normalize_and_fingerprint(tool, payload)
            asset_id, endpoint_id = _derive_ids_for_finding(conn, scan_id=scan_id, tool=tool, payload=normalized_payload)
            res = conn.execute(
                stmt,
                {
                    "id": scan_id,
                    "tool": tool,
                    "fp": fingerprint,
                    "asset_id": asset_id,
                    "endpoint_id": endpoint_id,
                    "p": json.dumps(normalized_payload),
                    "c": now,
                },
            )
            row = None
            try:
                row = res.mappings().first()
            except Exception:
                row = None
            if row and row.get("id") is not None:
                _apply_mitre_mapping(conn, finding_id=int(row["id"]), tool=tool, payload=normalized_payload)
            try:
                inserted += int(res.rowcount or 0)
            except Exception:
                inserted += 1

    return inserted


def set_status(scan_id: str, status: str):
    with engine.begin() as conn:
        conn.execute(text("UPDATE scans SET status=:s WHERE id=:id"), {"s": status, "id": scan_id})


def get_next_scan():
    with engine.begin() as conn:
        row = conn.execute(
            text(
                """
                SELECT id, target, api_key_id, triggered_by, concurrency_cap
                FROM scans
                WHERE status='queued'
                ORDER BY created_at ASC
                LIMIT 1
                """
            )
        ).mappings().first()
    return row


def normalize_target(target: str) -> tuple[str, bool]:
    """
    Returns (normalized_target, is_url_mode)
    URL mode if:
      - starts with http(s)
      - contains ":" (e.g., localhost:3000)
      - equals localhost/127.0.0.1
    Also converts localhost/127.0.0.1 to host.docker.internal for Docker -> host access.
    """
    is_url_mode = (
        target.startswith("http://")
        or target.startswith("https://")
        or ":" in target
        or target in ["localhost", "127.0.0.1"]
    )

    if "localhost" in target or "127.0.0.1" in target:
        target = target.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal")

    # In URL mode, ensure scheme
    if is_url_mode and not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target

    return target, is_url_mode


def load_pipeline_config(name: str) -> dict:
    path = os.path.join(os.path.dirname(__file__), "pipelines", f"{name}.yml")
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def run_pipeline(scan_id: str, target: str, mode: str):
    pipeline = load_pipeline_config(PIPELINE)
    tools = pipeline.get("tools") or []

    # Per-scan concurrency cap: used to clamp tool-level concurrency flags.
    # (Worker processes one scan at a time, so this mainly limits tool internals.)
    scan_concurrency_cap = os.getenv("SCAN_CONCURRENCY_CAP")
    try:
        scan_concurrency_cap_int = int(scan_concurrency_cap) if scan_concurrency_cap not in (None, "") else None
    except Exception:
        scan_concurrency_cap_int = None

    ctx: dict = {
        "scan_id": scan_id,
        "target": target,
        "mode": mode,
        "fast_mode": FAST_MODE,
        "subdomains": [],
        "urls": [],
        "katana_urls": [],
        "ffuf_urls": [],
        "concurrency_cap": scan_concurrency_cap_int,
        # Inject helpers for plugins
        "run": run,
        "log": log,
        "env": dict(os.environ),
        "insert_finding": insert_finding,
        "insert_findings_bulk": insert_findings_bulk,
    }

    for spec in tools:
        name = spec.get("name")
        if not name:
            continue

        stage = str(spec.get("stage") or "run")

        timeout = int(spec.get("timeout", 600))
        args = spec.get("args") or {}

        # Clamp common concurrency knobs as a basic per-scan rate limit.
        cap = ctx.get("concurrency_cap")
        if cap is not None:
            for key in ("concurrency", "threads", "workers"):
                if key in args:
                    try:
                        args[key] = min(int(args[key]), int(cap))
                    except Exception:
                        pass

        enabled = bool(spec.get("enabled", True))

        queued_at = _utcnow()
        base_dir = os.path.join(TOOL_RUNS_DIR, scan_id, name)
        _ensure_dir(base_dir)

        # Create the DB row first so we can attribute stdout/stderr and any early failures.
        # attempt is computed in-DB for (scan_id, tool).
        run_id, attempt = create_tool_run(
            scan_id=scan_id,
            tool=name,
            status="queued",
            queued_at=queued_at,
            stdout_path=None,
            stderr_path=None,
            artifact_path=None,
            args=args,
            short_error=None,
            metadata={"stage": stage, "timeout_s": timeout, "pipeline": PIPELINE, "mode": mode, "fast_mode": FAST_MODE},
        )

        artifact_dir = os.path.join(base_dir, f"attempt_{attempt}_{run_id}")
        _ensure_dir(artifact_dir)
        stdout_path = os.path.join(artifact_dir, "stdout.txt")
        stderr_path = os.path.join(artifact_dir, "stderr.txt")
        open(stdout_path, "a").close()
        open(stderr_path, "a").close()

        scan_artifacts_dir = os.path.join(ARTIFACTS_DIR, scan_id)
        _ensure_dir(scan_artifacts_dir)

        artifact_name = spec.get("artifact_name") or PRIMARY_ARTIFACT_NAMES.get(name) or f"{name}.artifact"
        # Avoid overwriting artifacts if retries happen.
        if attempt and int(attempt) > 1:
            if "." in artifact_name:
                base, ext = artifact_name.rsplit(".", 1)
                artifact_name = f"{base}_attempt{attempt}.{ext}"
            else:
                artifact_name = f"{artifact_name}_attempt{attempt}"
        artifact_path = os.path.join(scan_artifacts_dir, str(artifact_name))
        open(artifact_path, "a").close()

        # Back-fill file paths now that attempt is known.
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    UPDATE tool_runs
                    SET stdout_path=:stdout_path, stderr_path=:stderr_path, artifact_path=:artifact_path
                    WHERE id=:id
                    """
                ),
                {"id": run_id, "stdout_path": stdout_path, "stderr_path": stderr_path, "artifact_path": artifact_path},
            )

        recorder = ToolRunRecorder(stdout_path=stdout_path, stderr_path=stderr_path)
        recorder.run_id = run_id
        recorder.tool = name
        ctx["_tool_run_recorder"] = recorder

        # Per-tool invocation context.
        ctx["tool_run_id"] = run_id
        ctx["tool_attempt"] = attempt
        ctx["artifact_path"] = artifact_path
        ctx["run_dir"] = artifact_dir
        ctx["scan_artifacts_dir"] = scan_artifacts_dir

        started_at = None

        if not enabled:
            finished_at = _utcnow()
            update_tool_run(
                run_id=run_id,
                status="canceled",
                finished_at=finished_at,
                duration_ms=0,
                exit_code=None,
                short_error="disabled",
            )
            insert_finding(
                scan_id,
                f"{name}_skipped",
                {"reason": "disabled", "tool_run_id": run_id, "attempt": attempt},
            )
            continue

        try:
            mod = load_tool(name)
            if not mod.can_run(ctx):
                finished_at = _utcnow()
                update_tool_run(
                    run_id=run_id,
                    status="canceled",
                    finished_at=finished_at,
                    duration_ms=_duration_ms(started_at, finished_at) or 0,
                    exit_code=None,
                    short_error="can_run=false",
                )
                insert_finding(scan_id, f"{name}_skipped", {"reason": "can_run=false", "tool_run_id": run_id, "attempt": attempt})
                continue

            log(f"running tool={name}")
            started_at = _utcnow()
            update_tool_run(run_id=run_id, status="running", started_at=started_at)

            # Make the tool's internal ctx.run calls update this tool's recorder.
            ctx["run"] = lambda cmd, timeout=timeout: run(cmd, timeout=timeout, recorder=recorder)

            payload = mod.run(ctx, timeout=timeout, args=args)
            insert_finding(
                scan_id,
                name,
                (payload if isinstance(payload, dict) else {"result": payload}) | {"tool_run_id": run_id, "attempt": attempt},
            )

            # Best-effort copy of known tool temp outputs into the artifact directory.
            for candidate in TOOL_ARTIFACTS.get(name, []):
                if os.path.exists(candidate):
                    try:
                        shutil.copy2(candidate, artifact_dir)
                    except Exception:
                        pass

            finished_at = _utcnow()
            update_tool_run(
                run_id=run_id,
                status="success",
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=_duration_ms(started_at, finished_at),
                exit_code=recorder.exit_code,
                short_error=None,
            )

        except subprocess.TimeoutExpired as e:
            finished_at = _utcnow()
            short_error = _tail(recorder.stderr_tail or str(e), 200)
            update_tool_run(
                run_id=run_id,
                status="timeout",
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=_duration_ms(started_at, finished_at),
                exit_code=None,
                short_error=short_error,
            )
            insert_finding(
                scan_id,
                f"{name}_timeout",
                {
                    "error": str(e),
                    "stderr_tail": recorder.stderr_tail,
                    "tool_run_id": run_id,
                    "attempt": attempt,
                    "stdout_path": stdout_path,
                    "stderr_path": stderr_path,
                    "artifact_path": artifact_path,
                },
            )

        except Exception as e:
            finished_at = _utcnow()
            short_error = _tail(recorder.stderr_tail or str(e), 200)
            update_tool_run(
                run_id=run_id,
                status="failed",
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=_duration_ms(started_at, finished_at),
                exit_code=recorder.exit_code if started_at else None,
                short_error=short_error,
            )
            insert_finding(
                scan_id,
                f"{name}_error",
                {
                    "error": str(e),
                    "stderr_tail": recorder.stderr_tail,
                    "tool_run_id": run_id,
                    "attempt": attempt,
                    "stdout_path": stdout_path,
                    "stderr_path": stderr_path,
                    "artifact_path": artifact_path,
                },
            )
        finally:
            # Restore default helper for safety in the next iteration.
            ctx["run"] = run


def main():
    log("starting worker")
    init_db()
    log("db ready, polling for scans...")

    while True:
        job = get_next_scan()
        if not job:
            time.sleep(2)
            continue

        scan_id = job["id"]
        raw_target = job["target"]

        # Per-scan cap from DB overrides env default.
        if job.get("concurrency_cap") is not None:
            os.environ["SCAN_CONCURRENCY_CAP"] = str(job.get("concurrency_cap"))

        log(
            f"picked scan {scan_id} target={raw_target} api_key_id={job.get('api_key_id')} triggered_by={job.get('triggered_by')}"
        )

        # Defense-in-depth: validate scope again in the worker.
        lab_mode = os.getenv("LAB_MODE", "0") == "1"
        try:
            allowlist = load_allowlist()
            validate_target(str(raw_target), allowlist=allowlist, lab_mode=lab_mode)
        except ScopeError as e:
            insert_finding(scan_id, "scope_rejected", {"error": str(e), "target": raw_target, "lab_mode": lab_mode})
            set_status(scan_id, "failed")
            log(f"scan {scan_id} rejected by scope gate: {e}")
            continue

        set_status(scan_id, "running")

        target, is_url_mode = normalize_target(raw_target)
        log(f"normalized target={target} url_mode={is_url_mode}")

        try:
            mode = "url" if is_url_mode else "recon"
            run_pipeline(scan_id, target, mode)

            set_status(scan_id, "done")
            log(f"scan {scan_id} done")

        except Exception as e:
            insert_finding(scan_id, "error", {"error": str(e)})
            set_status(scan_id, "failed")
            log(f"scan {scan_id} failed: {e}")


if __name__ == "__main__":
    main()
