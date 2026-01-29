import os
import uuid
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import create_engine, text

from auth import authenticate_request
from scope_controls import ScopeError, load_allowlist, validate_target
from reporting import compute_scan_summary, render_scan_report_md

DATABASE_URL = os.environ["DATABASE_URL"]
engine = create_engine(DATABASE_URL, future=True)

app = FastAPI(title="AI Red Team Operator (MVP)")


def _get_scan_bundle(scan_id: str) -> tuple[dict, list[dict], list[dict]]:
    with engine.begin() as conn:
        scan = conn.execute(text("SELECT * FROM scans WHERE id=:id"), {"id": scan_id}).mappings().first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        findings = conn.execute(
            text(
                """
                SELECT
                  f.tool,
                  f.fingerprint,
                  f.payload,
                  f.created_at,
                  f.asset_id,
                  f.endpoint_id,
                  e.url AS endpoint_url,
                  e.method AS endpoint_method,
                  e.status AS endpoint_status,
                  e.title AS endpoint_title,
                  e.source AS endpoint_source,
                  a.host AS asset_host,
                  a.port AS asset_port,
                  a.scheme AS asset_scheme
                FROM findings f
                LEFT JOIN endpoints e ON e.id = f.endpoint_id
                LEFT JOIN assets a ON a.id = f.asset_id
                WHERE f.scan_id = :id
                ORDER BY f.id ASC
                """
            ),
            {"id": scan_id},
        ).mappings().all()

        tool_runs = conn.execute(
            text(
                """
                SELECT id, tool, status, attempt, queued_at, started_at, finished_at, duration_ms, exit_code,
                       stdout_path, stderr_path, artifact_path, args, short_error, metadata
                FROM tool_runs
                WHERE scan_id=:id
                ORDER BY queued_at ASC, tool ASC, attempt ASC
                """
            ),
            {"id": scan_id},
        ).mappings().all()

    return dict(scan), [dict(r) for r in tool_runs], [dict(f) for f in findings]

# Create tables on startup (simple MVP)
@app.on_event("startup")
def init_db():
    with engine.begin() as conn:
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS scans (
          id TEXT PRIMARY KEY,
          target TEXT NOT NULL,
          api_key_id TEXT NOT NULL DEFAULT 'unknown',
          triggered_by TEXT NOT NULL DEFAULT 'local',
          concurrency_cap INT NULL,
          status TEXT NOT NULL,
          created_at TIMESTAMP NOT NULL
        );
        """))

        # Add new columns to existing installs (best-effort in-app migration).
        conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS api_key_id TEXT NOT NULL DEFAULT 'unknown'"))
        conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS triggered_by TEXT NOT NULL DEFAULT 'local'"))
        conn.execute(text("ALTER TABLE scans ALTER COLUMN triggered_by SET DEFAULT 'local'"))
        conn.execute(text("UPDATE scans SET triggered_by='local' WHERE triggered_by='unknown'"))
        conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS concurrency_cap INT NULL"))

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

        # Assets/endpoints tables (scan-scoped; minimal fields for reporting + linking).
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
        conn.execute(text("""
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
        """))

        conn.execute(text("""
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
        """))

        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_tool_runs_scan_timeline ON tool_runs (scan_id, queued_at)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_tool_runs_scan_tool_attempt ON tool_runs (scan_id, tool, attempt)"))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_tool_runs_failed_recent
            ON tool_runs (finished_at DESC)
            WHERE status IN ('failed','timeout')
        """))

@app.post("/scan")
def create_scan(body: dict, request: Request):
    api_key_id, _secret = authenticate_request(request)

    target = body.get("target")
    if not target:
        raise HTTPException(status_code=400, detail="Missing target")

    # Who launched the scan:
    # - default: 'local'
    # - optionally accept a username from X-Username
    # - keep X-Triggered-By/body/env for compatibility
    triggered_by = (
        request.headers.get("X-Username")
        or request.headers.get("X-Triggered-By")
        or body.get("triggered_by")
        or os.getenv("TRIGGERED_BY", "local")
    )

    concurrency_cap = body.get("concurrency_cap")
    if concurrency_cap is None:
        concurrency_cap = os.getenv("SCAN_CONCURRENCY_CAP")
    try:
        concurrency_cap = int(concurrency_cap) if concurrency_cap not in (None, "") else None
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid concurrency_cap")

    lab_mode = os.getenv("LAB_MODE", "0") == "1"
    try:
        allowlist = load_allowlist()
        validation = validate_target(str(target), allowlist=allowlist, lab_mode=lab_mode)
    except ScopeError as e:
        raise HTTPException(status_code=400, detail=f"Scope rejected: {e}")

    scan_id = str(uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO scans (id, target, api_key_id, triggered_by, concurrency_cap, status, created_at)
                VALUES (:id,:t,:kid,:by,:cap,:s,:c)
                """
            ),
            {
                "id": scan_id,
                "t": str(target),
                "kid": str(api_key_id),
                "by": str(triggered_by),
                "cap": concurrency_cap,
                "s": "queued",
                "c": datetime.utcnow(),
            },
        )
    return {
        "scan_id": scan_id,
        "status": "queued",
        "api_key_id": str(api_key_id),
        "triggered_by": str(triggered_by),
        "concurrency_cap": concurrency_cap,
        "scope": validation,
    }

@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    # Legacy endpoint kept for compatibility.
    # NOTE: Historically returned {"error":"Not found"} instead of 404.
    try:
        scan, tool_runs, findings = _get_scan_bundle(scan_id)
    except HTTPException as e:
        if e.status_code == 404:
            return {"error": "Not found"}
        raise
    return {"scan": scan, "tool_runs": tool_runs, "findings": findings}


@app.get("/scans")
def list_scans(limit: int = 50, offset: int = 0, status: str | None = None):
    """List scans (newest first) so you can retrieve old scan IDs for reports."""

    if limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 200")
    if offset < 0:
        raise HTTPException(status_code=400, detail="offset must be >= 0")

    where = ""
    params: dict = {"limit": int(limit), "offset": int(offset)}
    if status:
        where = "WHERE status = :status"
        params["status"] = str(status)

    with engine.begin() as conn:
        rows = conn.execute(
            text(
                f"""
                SELECT id, target, api_key_id, triggered_by, concurrency_cap, status, created_at
                FROM scans
                {where}
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            params,
        ).mappings().all()

    return {"scans": [dict(r) for r in rows], "limit": int(limit), "offset": int(offset), "status": status}


@app.get("/scans/{scan_id}/summary")
def get_scan_summary(scan_id: str):
    scan, tool_runs, findings = _get_scan_bundle(scan_id)
    return compute_scan_summary(scan=scan, tool_runs=tool_runs, findings=findings)


@app.get("/scans/{scan_id}/report.md")
def get_scan_report_md(scan_id: str):
    scan, tool_runs, findings = _get_scan_bundle(scan_id)
    md = render_scan_report_md(scan=scan, tool_runs=tool_runs, findings=findings)
    return PlainTextResponse(content=md, media_type="text/markdown; charset=utf-8")
