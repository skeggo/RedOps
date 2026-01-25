import os
import json
import time
import uuid
import subprocess
import shutil
from datetime import datetime
from sqlalchemy import create_engine, text

import yaml

from tools.plugin import load_tool
from scope_controls import ScopeError, load_allowlist, validate_target

DATABASE_URL = os.environ["DATABASE_URL"]
engine = create_engine(DATABASE_URL, future=True)

FAST_MODE = os.getenv("FAST_MODE", "1") == "1"
PIPELINE = os.getenv("PIPELINE", "default")


def log(msg: str):
    print(f"[worker] {msg}", flush=True)


def init_db():
    with engine.begin() as conn:
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS scans (
          id TEXT PRIMARY KEY,
          target TEXT NOT NULL,
          api_key_id TEXT NOT NULL DEFAULT 'unknown',
          triggered_by TEXT NOT NULL DEFAULT 'unknown',
          concurrency_cap INT NULL,
          status TEXT NOT NULL,
          created_at TIMESTAMP NOT NULL
        );
        """))

        # Add new columns to existing installs (best-effort in-app migration).
        conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS api_key_id TEXT NOT NULL DEFAULT 'unknown'"))
        conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS triggered_by TEXT NOT NULL DEFAULT 'unknown'"))
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
            """
            )
        )

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


def run(cmd: list[str], timeout: int = 600, recorder: ToolRunRecorder | None = None) -> str:
    log("CMD: " + " ".join(cmd))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        stderr = None
        if getattr(e, "stderr", None):
            stderr = e.stderr
        elif getattr(e, "output", None):
            stderr = e.output
        if recorder:
            recorder.observe_timeout(stderr=stderr)
        raise

    if recorder:
        recorder.observe(p.returncode, p.stdout, p.stderr)

    if p.returncode != 0:
        log("STDERR: " + (_tail(p.stderr, 500) or ""))

    return (p.stdout or "").strip()


def insert_finding(scan_id: str, tool: str, payload: dict):
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO findings (scan_id, tool, payload, created_at) VALUES (:id,:tool,:p,:c)"),
            {"id": scan_id, "tool": tool, "p": json.dumps(payload), "c": datetime.utcnow()},
        )


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
        "concurrency_cap": scan_concurrency_cap_int,
        # Inject helpers for plugins
        "run": run,
        "log": log,
        "env": dict(os.environ),
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
                {"id": run_id, "stdout_path": stdout_path, "stderr_path": stderr_path, "artifact_path": artifact_dir},
            )

        recorder = ToolRunRecorder(stdout_path=stdout_path, stderr_path=stderr_path)
        ctx["_tool_run_recorder"] = recorder

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
            short_error = _tail(str(e), 200)
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
                {"error": str(e), "tool_run_id": run_id, "attempt": attempt},
            )

        except Exception as e:
            finished_at = _utcnow()
            short_error = _tail(str(e), 200)
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
                {"error": str(e), "tool_run_id": run_id, "attempt": attempt},
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
