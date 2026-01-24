import os
import json
import time
import subprocess
from datetime import datetime
from sqlalchemy import create_engine, text

import yaml

from tools.plugin import load_tool

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
          status TEXT NOT NULL,
          created_at TIMESTAMP NOT NULL
        );
        """))
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS findings (
          id SERIAL PRIMARY KEY,
          scan_id TEXT NOT NULL,
          tool TEXT NOT NULL,
          payload JSONB NOT NULL,
          created_at TIMESTAMP NOT NULL
        );
        """))


def run(cmd: list[str], timeout: int = 600) -> str:
    log("CMD: " + " ".join(cmd))
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        log("STDERR: " + (p.stderr[-500:] if p.stderr else ""))
    return p.stdout.strip()


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
            text("SELECT id, target FROM scans WHERE status='queued' ORDER BY created_at ASC LIMIT 1")
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

    ctx: dict = {
        "scan_id": scan_id,
        "target": target,
        "mode": mode,
        "fast_mode": FAST_MODE,
        "subdomains": [],
        "urls": [],
        # Inject helpers for plugins
        "run": run,
        "log": log,
        "env": dict(os.environ),
    }

    for spec in tools:
        name = spec.get("name")
        if not name:
            continue

        enabled = bool(spec.get("enabled", True))
        if not enabled:
            insert_finding(scan_id, f"{name}_skipped", {"reason": "disabled"})
            continue

        timeout = int(spec.get("timeout", 600))
        args = spec.get("args") or {}

        try:
            mod = load_tool(name)
            if not mod.can_run(ctx):
                insert_finding(scan_id, f"{name}_skipped", {"reason": "can_run=false"})
                continue

            log(f"running tool={name}")
            payload = mod.run(ctx, timeout=timeout, args=args)
            insert_finding(scan_id, name, payload if isinstance(payload, dict) else {"result": payload})
        except Exception as e:
            insert_finding(scan_id, f"{name}_error", {"error": str(e)})


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

        set_status(scan_id, "running")
        log(f"picked scan {scan_id} target={raw_target}")

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
