-- Migration: api keys v1
--
-- Adds API-key attribution fields to scans.

BEGIN;

ALTER TABLE public.scans
  ADD COLUMN IF NOT EXISTS api_key_id TEXT NOT NULL DEFAULT 'unknown';

COMMIT;
