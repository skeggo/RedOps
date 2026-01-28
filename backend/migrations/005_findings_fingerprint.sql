-- Migration: add stable finding fingerprints for dedupe

ALTER TABLE public.findings
  ADD COLUMN IF NOT EXISTS fingerprint TEXT NULL;

-- Partial unique index so legacy rows (NULL fingerprint) don't block migration.
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_scan_fingerprint_unique
  ON public.findings (scan_id, fingerprint)
  WHERE fingerprint IS NOT NULL;
