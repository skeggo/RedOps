-- Migration: assets + endpoints tables (scan-scoped)
--
-- Minimal schema to support reporting and linking findings to an asset/endpoint.
-- Keep it simple: no full CMDB, no historical tracking.

BEGIN;

CREATE TABLE IF NOT EXISTS public.assets (
  id SERIAL PRIMARY KEY,
  scan_id TEXT NOT NULL,
  host TEXT NOT NULL,
  port INT NULL,
  scheme TEXT NULL,
  tech JSONB NULL,
  headers_summary JSONB NULL,
  discovered_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_assets_scan_id ON public.assets (scan_id);
CREATE INDEX IF NOT EXISTS idx_assets_host ON public.assets (host);

CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_scan_host_port_scheme_unique
  ON public.assets (scan_id, host, port, scheme);


CREATE TABLE IF NOT EXISTS public.endpoints (
  id SERIAL PRIMARY KEY,
  scan_id TEXT NOT NULL,
  asset_id INT NULL,
  url TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT '',
  status INT NULL,
  title TEXT NULL,
  source TEXT NOT NULL,
  discovered_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_endpoints_scan_id ON public.endpoints (scan_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_asset_id ON public.endpoints (asset_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_url ON public.endpoints (url);

CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoints_scan_url_method_unique
  ON public.endpoints (scan_id, url, method);


ALTER TABLE public.findings
  ADD COLUMN IF NOT EXISTS asset_id INT NULL;

ALTER TABLE public.findings
  ADD COLUMN IF NOT EXISTS endpoint_id INT NULL;

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON public.findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON public.findings (asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_endpoint_id ON public.findings (endpoint_id);

COMMIT;
