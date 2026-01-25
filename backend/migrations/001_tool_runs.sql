-- Migration: tool_runs v2 (execution tracking)
--
-- Goals:
-- - Track multiple tools per scan and multiple attempts (retries) per tool.
-- - Provide timestamps for lifecycle debugging (queued/running/success/failed/timeout/canceled).
-- - Store file paths for stdout/stderr and tool artifacts (paths only; content stays on disk).
--
-- NOTE:
-- If an old tool_runs table exists (legacy MVP schema), it will be renamed to tool_runs_legacy
-- and best-effort copied into the new table.

BEGIN;

-- Needed for gen_random_uuid() used during legacy backfill.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'tool_runs'
  ) THEN
    -- Legacy MVP table had no `id` column.
    IF NOT EXISTS (
      SELECT 1
      FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'tool_runs' AND column_name = 'id'
    ) THEN
      IF NOT EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'tool_runs_legacy'
      ) THEN
        ALTER TABLE public.tool_runs RENAME TO tool_runs_legacy;
      END IF;
    END IF;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.tool_runs (
  id UUID PRIMARY KEY,
  scan_id TEXT NOT NULL,
  tool TEXT NOT NULL,

  -- Lifecycle status for the tool execution.
  -- Use 'canceled' when a tool is skipped/disabled or cannot run in the current context.
  status TEXT NOT NULL,

  -- Attempt number for this (scan_id, tool) pair. Starts at 1.
  attempt INT NOT NULL,

  queued_at TIMESTAMP NOT NULL,
  started_at TIMESTAMP NULL,
  finished_at TIMESTAMP NULL,
  duration_ms BIGINT NULL,

  exit_code INT NULL,

  -- Paths inside the worker container; content stored on disk.
  stdout_path TEXT NULL,
  stderr_path TEXT NULL,
  artifact_path TEXT NULL,

  -- Only sanitized configuration inputs from pipeline/tool spec.
  args JSONB NOT NULL DEFAULT '{}'::jsonb,

  -- Short human-readable error summary for quick triage.
  short_error TEXT NULL,

  -- Optional structured metadata (e.g., stage name, timeouts, tool versions).
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Enforce attempts are positive and unique per tool per scan.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'tool_runs_attempt_positive'
  ) THEN
    ALTER TABLE public.tool_runs
      ADD CONSTRAINT tool_runs_attempt_positive CHECK (attempt >= 1);
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'tool_runs_scan_tool_attempt_unique'
  ) THEN
    ALTER TABLE public.tool_runs
      ADD CONSTRAINT tool_runs_scan_tool_attempt_unique UNIQUE (scan_id, tool, attempt);
  END IF;
END $$;

-- Per-scan timelines (fast ordered retrieval).
CREATE INDEX IF NOT EXISTS idx_tool_runs_scan_timeline
  ON public.tool_runs (scan_id, queued_at);

-- Common lookup (tool + attempt history within a scan).
CREATE INDEX IF NOT EXISTS idx_tool_runs_scan_tool_attempt
  ON public.tool_runs (scan_id, tool, attempt);

-- Debugging failed executions (triage recent failures quickly).
CREATE INDEX IF NOT EXISTS idx_tool_runs_failed_recent
  ON public.tool_runs (finished_at DESC)
  WHERE status IN ('failed', 'timeout');

-- Legacy backfill (best-effort). Keeps legacy table for reference.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'tool_runs_legacy'
  ) THEN
    -- Avoid double-inserting if migration is re-run.
    IF NOT EXISTS (SELECT 1 FROM public.tool_runs LIMIT 1) THEN
      INSERT INTO public.tool_runs (
        id,
        scan_id,
        tool,
        status,
        attempt,
        queued_at,
        started_at,
        finished_at,
        duration_ms,
        exit_code,
        stdout_path,
        stderr_path,
        artifact_path,
        args,
        short_error,
        metadata
      )
      SELECT
        gen_random_uuid(),
        scan_id,
        tool,
        CASE status
          WHEN 'done' THEN 'success'
          ELSE status
        END,
        1,
        COALESCE(started_at, finished_at, now()),
        started_at,
        finished_at,
        duration_ms,
        exit_code,
        NULL,
        NULL,
        NULL,
        '{}'::jsonb,
        CASE
          WHEN status IN ('failed', 'timeout') THEN left(coalesce(stderr_tail, ''), 200)
          ELSE NULL
        END,
        jsonb_build_object(
          'legacy_stage', stage,
          'legacy_stderr_tail', stderr_tail
        )
      FROM public.tool_runs_legacy;
    END IF;
  END IF;
END $$;

COMMIT;
