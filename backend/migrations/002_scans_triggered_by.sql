-- Migration: scans.triggered_by default + backfill
--
-- Purpose: store who launched a scan.
-- - Default is 'local'
-- - Later we can store API key IDs separately (already via scans.api_key_id)

BEGIN;

ALTER TABLE public.scans
  ADD COLUMN IF NOT EXISTS triggered_by TEXT NOT NULL DEFAULT 'local';

-- Ensure a consistent default even if the column already existed.
ALTER TABLE public.scans
  ALTER COLUMN triggered_by SET DEFAULT 'local';

-- Best-effort backfill from older default values.
UPDATE public.scans
  SET triggered_by = 'local'
  WHERE triggered_by IN ('unknown', '');

COMMIT;
