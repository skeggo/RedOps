-- Migration: MITRE ATT&CK mapping (rules-based v1)
--
-- Tables:
-- - mitre_techniques: technique_id (T####), name, tactic
-- - finding_mitre: finding_id, technique_id, confidence, reason, source='rules'

BEGIN;

CREATE TABLE IF NOT EXISTS public.mitre_techniques (
  technique_id TEXT PRIMARY KEY,
  name TEXT NULL,
  tactic TEXT NULL
);


CREATE TABLE IF NOT EXISTS public.finding_mitre (
  finding_id INT NOT NULL,
  technique_id TEXT NOT NULL,
  confidence DOUBLE PRECISION NULL,
  reason TEXT NULL,
  source TEXT NOT NULL DEFAULT 'rules',
  CONSTRAINT finding_mitre_finding_fk FOREIGN KEY (finding_id)
    REFERENCES public.findings(id) ON DELETE CASCADE,
  CONSTRAINT finding_mitre_technique_fk FOREIGN KEY (technique_id)
    REFERENCES public.mitre_techniques(technique_id) ON DELETE RESTRICT,
  CONSTRAINT finding_mitre_unique UNIQUE (finding_id, technique_id, source)
);

CREATE INDEX IF NOT EXISTS idx_finding_mitre_finding_id ON public.finding_mitre (finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_mitre_technique_id ON public.finding_mitre (technique_id);

COMMIT;
