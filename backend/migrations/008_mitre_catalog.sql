-- Migration: MITRE catalog tables (RedOps-friendly)
--
-- Extends the minimal v1 schema by adding:
-- - richer fields on mitre_techniques
-- - mitre_tactics + technique<->tactic join table
-- - mitre_sync_state for tracking catalog version/sync health

BEGIN;

ALTER TABLE public.mitre_techniques
  ADD COLUMN IF NOT EXISTS description TEXT NULL;

ALTER TABLE public.mitre_techniques
  ADD COLUMN IF NOT EXISTS url TEXT NULL;

ALTER TABLE public.mitre_techniques
  ADD COLUMN IF NOT EXISTS revoked BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE public.mitre_techniques
  ADD COLUMN IF NOT EXISTS deprecated BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE public.mitre_techniques
  ADD COLUMN IF NOT EXISTS modified TIMESTAMP NULL;


CREATE TABLE IF NOT EXISTS public.mitre_tactics (
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

CREATE INDEX IF NOT EXISTS idx_mitre_tactics_shortname ON public.mitre_tactics (shortname);


CREATE TABLE IF NOT EXISTS public.mitre_technique_tactics (
  technique_id TEXT NOT NULL,
  tactic_id TEXT NOT NULL,
  CONSTRAINT mitre_tt_technique_fk FOREIGN KEY (technique_id)
    REFERENCES public.mitre_techniques(technique_id) ON DELETE CASCADE,
  CONSTRAINT mitre_tt_tactic_fk FOREIGN KEY (tactic_id)
    REFERENCES public.mitre_tactics(tactic_id) ON DELETE CASCADE,
  CONSTRAINT mitre_tt_unique UNIQUE (technique_id, tactic_id)
);

CREATE INDEX IF NOT EXISTS idx_mitre_tt_technique_id ON public.mitre_technique_tactics (technique_id);
CREATE INDEX IF NOT EXISTS idx_mitre_tt_tactic_id ON public.mitre_technique_tactics (tactic_id);


CREATE TABLE IF NOT EXISTS public.mitre_sync_state (
  dataset TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  attack_version TEXT NULL,
  last_synced_at TIMESTAMP NULL,
  last_error TEXT NULL
);

COMMIT;
