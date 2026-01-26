import os
import uuid
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request
from sqlalchemy import create_engine, text

from auth import authenticate_request
from scope_controls import ScopeError, load_allowlist, validate_target

DATABASE_URL = os.environ["DATABASE_URL"]
engine = create_engine(DATABASE_URL, future=True)

app = FastAPI(title="AI Red Team Operator (MVP)")

# Create tables on startup (simple MVP)
@app.on_event("startup")
def init_db():
    with engine.begin() as conn:
        conn.execute(text("""
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
        """))

        # Add new columns to existing installs (best-effort in-app migration).
        conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS api_key_id TEXT NULL"))
        conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS triggered_by TEXT NOT NULL DEFAULT 'local'"))
        conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS triggered_via TEXT NOT NULL DEFAULT 'api'"))
        conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS request_ip INET NULL"))

        # Align legacy defaults.
        conn.execute(text("ALTER TABLE scans ALTER COLUMN triggered_by SET DEFAULT 'local'"))
        conn.execute(text("ALTER TABLE scans ALTER COLUMN triggered_via SET DEFAULT 'api'"))
        conn.execute(text("UPDATE scans SET triggered_by='local' WHERE triggered_by='unknown'"))

        # api_key_id used to be NOT NULL DEFAULT 'unknown' (older installs). Make it nullable.
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
        conn.execute(text("UPDATE scans SET api_key_id=NULL WHERE api_key_id='unknown'"))
        conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS concurrency_cap INT NULL"))
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS findings (
          id SERIAL PRIMARY KEY,
          scan_id TEXT NOT NULL,
          tool TEXT NOT NULL,
          payload JSONB NOT NULL,
          created_at TIMESTAMP NOT NULL
        );
        """))

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
    # - Prefer X-Actor
    # - Fallback to DEFAULT_TRIGGERED_BY
    default_triggered_by = os.getenv("DEFAULT_TRIGGERED_BY", "local")
    triggered_by = (
        request.headers.get("X-Actor")
        or request.headers.get("X-Username")
        or request.headers.get("X-Triggered-By")
        or body.get("triggered_by")
        or default_triggered_by
    )

    triggered_via = (
        request.headers.get("X-Triggered-Via")
        or body.get("triggered_via")
        or os.getenv("DEFAULT_TRIGGERED_VIA", "api")
    )

    request_ip = None
    if request.client and request.client.host:
        request_ip = request.client.host

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
                INSERT INTO scans (id, target, api_key_id, triggered_by, triggered_via, request_ip, concurrency_cap, status, created_at)
                VALUES (:id,:t,:kid,:by,:via,:ip,:cap,:s,:c)
                """
            ),
            {
                "id": scan_id,
                "t": str(target),
                "kid": str(api_key_id) if api_key_id is not None else None,
                "by": str(triggered_by),
                "via": str(triggered_via),
                "ip": request_ip,
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
        "triggered_via": str(triggered_via),
        "request_ip": request_ip,
        "concurrency_cap": concurrency_cap,
        "scope": validation,
    }

@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    with engine.begin() as conn:
        scan = conn.execute(text("SELECT * FROM scans WHERE id=:id"), {"id": scan_id}).mappings().first()
        if not scan:
            return {"error": "Not found"}
        findings = conn.execute(
            text("SELECT tool, payload, created_at FROM findings WHERE scan_id=:id ORDER BY id ASC"),
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

    return {"scan": dict(scan), "tool_runs": [dict(r) for r in tool_runs], "findings": [dict(f) for f in findings]}
