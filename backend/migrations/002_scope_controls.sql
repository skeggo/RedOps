-- Migration: scope controls v1
--
-- Adds provenance and safety-related fields to scans.

BEGIN;

ALTER TABLE public.scans
  ADD COLUMN IF NOT EXISTS triggered_by TEXT NOT NULL DEFAULT 'unknown';

ALTER TABLE public.scans
  ADD COLUMN IF NOT EXISTS concurrency_cap INT NULL;

COMMIT;
