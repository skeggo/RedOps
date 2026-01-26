-- Migration: scans trigger metadata (v1)
--
-- Adds:
-- - triggered_via: how the scan was started (api/webhook/scheduler)
-- - request_ip: originating requester IP (optional)
-- Makes:
-- - api_key_id nullable (we store key IDs today; later can be UUID/int)

BEGIN;

ALTER TABLE public.scans
  ADD COLUMN IF NOT EXISTS triggered_via TEXT NOT NULL DEFAULT 'api';

ALTER TABLE public.scans
  ADD COLUMN IF NOT EXISTS request_ip INET NULL;

-- api_key_id used to be NOT NULL DEFAULT 'unknown'. Make it nullable for later.
ALTER TABLE public.scans
  ADD COLUMN IF NOT EXISTS api_key_id TEXT;

DO $$
BEGIN
  ALTER TABLE public.scans ALTER COLUMN api_key_id DROP NOT NULL;
EXCEPTION WHEN others THEN
  NULL;
END $$;

DO $$
BEGIN
  ALTER TABLE public.scans ALTER COLUMN api_key_id DROP DEFAULT;
EXCEPTION WHEN others THEN
  NULL;
END $$;

UPDATE public.scans SET api_key_id = NULL WHERE api_key_id = 'unknown';
UPDATE public.scans SET triggered_by = 'local' WHERE triggered_by IN ('unknown', '');

COMMIT;
