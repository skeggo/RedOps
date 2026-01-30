from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.request import Request, urlopen

from sqlalchemy import create_engine, text


ENTERPRISE_ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


@dataclass(frozen=True)
class ParsedTactic:
    tactic_id: str
    name: str
    shortname: str
    description: str | None
    url: str | None
    revoked: bool
    deprecated: bool
    modified: datetime | None


@dataclass(frozen=True)
class ParsedTechnique:
    technique_id: str
    name: str
    description: str | None
    url: str | None
    revoked: bool
    deprecated: bool
    modified: datetime | None
    tactic_shortnames: tuple[str, ...]


def _parse_stix_ts(v: object) -> datetime | None:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    # STIX timestamps are ISO8601 (usually Z). Python's fromisoformat doesn't accept Z.
    s = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _external_id(stix_obj: dict[str, Any], source_name: str) -> str | None:
    refs = stix_obj.get("external_references")
    if not isinstance(refs, list):
        return None
    for r in refs:
        if not isinstance(r, dict):
            continue
        if str(r.get("source_name") or "") != source_name:
            continue
        ext = r.get("external_id")
        if ext:
            return str(ext)
    return None


def _external_url(stix_obj: dict[str, Any], source_name: str) -> str | None:
    refs = stix_obj.get("external_references")
    if not isinstance(refs, list):
        return None
    for r in refs:
        if not isinstance(r, dict):
            continue
        if str(r.get("source_name") or "") != source_name:
            continue
        url = r.get("url")
        if url:
            return str(url)
    return None


def parse_enterprise_attack_bundle(bundle: dict[str, Any]) -> tuple[list[ParsedTactic], list[ParsedTechnique]]:
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        return [], []

    tactics: list[ParsedTactic] = []
    tactics_by_short: dict[str, ParsedTactic] = {}

    for o in objects:
        if not isinstance(o, dict):
            continue
        if str(o.get("type") or "") != "x-mitre-tactic":
            continue

        tactic_id = _external_id(o, "mitre-attack")
        if not tactic_id:
            continue

        shortname = str(o.get("x_mitre_shortname") or "").strip()
        name = str(o.get("name") or "").strip()
        if not shortname or not name:
            continue

        pt = ParsedTactic(
            tactic_id=tactic_id,
            name=name,
            shortname=shortname,
            description=str(o.get("description")) if o.get("description") is not None else None,
            url=_external_url(o, "mitre-attack"),
            revoked=bool(o.get("revoked") is True),
            deprecated=bool(o.get("x_mitre_deprecated") is True),
            modified=_parse_stix_ts(o.get("modified")),
        )
        tactics.append(pt)
        tactics_by_short[shortname] = pt

    techniques: list[ParsedTechnique] = []
    for o in objects:
        if not isinstance(o, dict):
            continue
        if str(o.get("type") or "") != "attack-pattern":
            continue

        technique_id = _external_id(o, "mitre-attack")
        if not technique_id:
            continue

        name = str(o.get("name") or "").strip()
        if not name:
            continue

        # Link to tactics via kill_chain_phases (phase_name == tactic shortname)
        tactic_shortnames: list[str] = []
        phases = o.get("kill_chain_phases")
        if isinstance(phases, list):
            for ph in phases:
                if not isinstance(ph, dict):
                    continue
                if str(ph.get("kill_chain_name") or "") != "mitre-attack":
                    continue
                phase_name = str(ph.get("phase_name") or "").strip()
                if not phase_name:
                    continue
                tactic_shortnames.append(phase_name)

        # Deduplicate but keep stable-ish order
        seen: set[str] = set()
        tactic_shortnames_dedup: list[str] = []
        for t in tactic_shortnames:
            if t in seen:
                continue
            seen.add(t)
            tactic_shortnames_dedup.append(t)

        techniques.append(
            ParsedTechnique(
                technique_id=technique_id,
                name=name,
                description=str(o.get("description")) if o.get("description") is not None else None,
                url=_external_url(o, "mitre-attack"),
                revoked=bool(o.get("revoked") is True),
                deprecated=bool(o.get("x_mitre_deprecated") is True),
                modified=_parse_stix_ts(o.get("modified")),
                tactic_shortnames=tuple(tactic_shortnames_dedup),
            )
        )

    return tactics, techniques


def fetch_json(url: str, *, timeout_s: int = 60) -> dict[str, Any]:
    req = Request(url, headers={"User-Agent": "ai-redteam-operator/mitre-sync"})
    with urlopen(req, timeout=timeout_s) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8", errors="replace"))


def sync_enterprise_attack(*, database_url: str, stix_url: str = ENTERPRISE_ATTACK_STIX_URL) -> None:
    bundle = fetch_json(stix_url)
    tactics, techniques = parse_enterprise_attack_bundle(bundle)

    engine = create_engine(database_url, future=True)

    now = datetime.utcnow()
    with engine.begin() as conn:
        # Ensure tables exist (for environments that haven't run migrations yet).
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS mitre_techniques (
                  technique_id TEXT PRIMARY KEY,
                  name TEXT NULL,
                  tactic TEXT NULL,
                  description TEXT NULL,
                  url TEXT NULL,
                  revoked BOOLEAN NOT NULL DEFAULT FALSE,
                  deprecated BOOLEAN NOT NULL DEFAULT FALSE,
                  modified TIMESTAMP NULL
                );
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS mitre_tactics (
                  tactic_id TEXT PRIMARY KEY,
                  name TEXT NOT NULL,
                  shortname TEXT NOT NULL,
                  description TEXT NULL,
                  url TEXT NULL,
                  revoked BOOLEAN NOT NULL DEFAULT FALSE,
                  deprecated BOOLEAN NOT NULL DEFAULT FALSE,
                  modified TIMESTAMP NULL,
                  CONSTRAINT mitre_tactics_shortname_unique UNIQUE (shortname)
                );
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS mitre_technique_tactics (
                  technique_id TEXT NOT NULL,
                  tactic_id TEXT NOT NULL,
                  CONSTRAINT mitre_tt_unique UNIQUE (technique_id, tactic_id)
                );
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS mitre_sync_state (
                  dataset TEXT PRIMARY KEY,
                  source TEXT NOT NULL,
                  attack_version TEXT NULL,
                  last_synced_at TIMESTAMP NULL,
                  last_error TEXT NULL
                );
                """
            )
        )

        # Upsert tactics
        tactic_stmt = text(
            """
            INSERT INTO mitre_tactics (tactic_id, name, shortname, description, url, revoked, deprecated, modified)
            VALUES (:tactic_id,:name,:shortname,:description,:url,:revoked,:deprecated,:modified)
            ON CONFLICT (tactic_id)
            DO UPDATE SET
              name = EXCLUDED.name,
              shortname = EXCLUDED.shortname,
              description = EXCLUDED.description,
              url = EXCLUDED.url,
              revoked = EXCLUDED.revoked,
              deprecated = EXCLUDED.deprecated,
              modified = COALESCE(EXCLUDED.modified, mitre_tactics.modified)
            """
        )
        for t in tactics:
            conn.execute(
                tactic_stmt,
                {
                    "tactic_id": t.tactic_id,
                    "name": t.name,
                    "shortname": t.shortname,
                    "description": t.description,
                    "url": t.url,
                    "revoked": bool(t.revoked),
                    "deprecated": bool(t.deprecated),
                    "modified": t.modified,
                },
            )

        # Build mapping shortname -> tactic_id
        rows = conn.execute(text("SELECT tactic_id, shortname FROM mitre_tactics")).mappings().all()
        tactic_id_by_short = {str(r.get("shortname")): str(r.get("tactic_id")) for r in rows if r.get("shortname") and r.get("tactic_id")}

        # Upsert techniques
        technique_stmt = text(
            """
            INSERT INTO mitre_techniques (technique_id, name, tactic, description, url, revoked, deprecated, modified)
            VALUES (:technique_id,:name,:tactic,:description,:url,:revoked,:deprecated,:modified)
            ON CONFLICT (technique_id)
            DO UPDATE SET
              name = EXCLUDED.name,
              tactic = COALESCE(NULLIF(EXCLUDED.tactic, ''), mitre_techniques.tactic),
              description = EXCLUDED.description,
              url = EXCLUDED.url,
              revoked = EXCLUDED.revoked,
              deprecated = EXCLUDED.deprecated,
              modified = COALESCE(EXCLUDED.modified, mitre_techniques.modified)
            """
        )

        link_stmt = text(
            """
            INSERT INTO mitre_technique_tactics (technique_id, tactic_id)
            VALUES (:technique_id,:tactic_id)
            ON CONFLICT (technique_id, tactic_id) DO NOTHING
            """
        )

        for tech in techniques:
            primary_tactic = tech.tactic_shortnames[0] if tech.tactic_shortnames else ""
            conn.execute(
                technique_stmt,
                {
                    "technique_id": tech.technique_id,
                    "name": tech.name,
                    "tactic": primary_tactic,
                    "description": tech.description,
                    "url": tech.url,
                    "revoked": bool(tech.revoked),
                    "deprecated": bool(tech.deprecated),
                    "modified": tech.modified,
                },
            )

            for short in tech.tactic_shortnames:
                tactic_id = tactic_id_by_short.get(short)
                if not tactic_id:
                    continue
                conn.execute(link_stmt, {"technique_id": tech.technique_id, "tactic_id": tactic_id})

        conn.execute(
            text(
                """
                INSERT INTO mitre_sync_state (dataset, source, attack_version, last_synced_at, last_error)
                VALUES ('enterprise-attack', :source, NULL, :ts, NULL)
                ON CONFLICT (dataset)
                DO UPDATE SET
                  source = EXCLUDED.source,
                  last_synced_at = EXCLUDED.last_synced_at,
                  last_error = NULL
                """
            ),
            {"source": stix_url, "ts": now},
        )


def main(argv: list[str]) -> int:
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        print("Missing DATABASE_URL", file=sys.stderr)
        return 2

    stix_url = os.getenv("MITRE_STIX_URL", ENTERPRISE_ATTACK_STIX_URL)
    try:
        sync_enterprise_attack(database_url=database_url, stix_url=stix_url)
    except Exception as e:
        # Record error best-effort.
        try:
            engine = create_engine(database_url, future=True)
            with engine.begin() as conn:
                conn.execute(
                    text(
                        """
                        CREATE TABLE IF NOT EXISTS mitre_sync_state (
                          dataset TEXT PRIMARY KEY,
                          source TEXT NOT NULL,
                          attack_version TEXT NULL,
                          last_synced_at TIMESTAMP NULL,
                          last_error TEXT NULL
                        );
                        """
                    )
                )
                conn.execute(
                    text(
                        """
                        INSERT INTO mitre_sync_state (dataset, source, attack_version, last_synced_at, last_error)
                        VALUES ('enterprise-attack', :source, NULL, NULL, :err)
                        ON CONFLICT (dataset)
                        DO UPDATE SET
                          source = EXCLUDED.source,
                          last_error = EXCLUDED.last_error
                        """
                    ),
                    {"source": os.getenv("MITRE_STIX_URL", ENTERPRISE_ATTACK_STIX_URL), "err": str(e)},
                )
        except Exception:
            pass

        print(f"MITRE sync failed: {e}", file=sys.stderr)
        return 1

    print("MITRE sync complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
