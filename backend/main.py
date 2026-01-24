import os
import uuid
from datetime import datetime
from fastapi import FastAPI
from sqlalchemy import create_engine, text

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

@app.post("/scan")
def create_scan(body: dict):
    target = body.get("target")
    if not target:
        return {"error": "Missing target"}

    scan_id = str(uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO scans (id, target, status, created_at) VALUES (:id,:t,:s,:c)"),
            {"id": scan_id, "t": target, "s": "queued", "c": datetime.utcnow()},
        )
    return {"scan_id": scan_id, "status": "queued"}

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

    return {"scan": dict(scan), "findings": [dict(f) for f in findings]}
