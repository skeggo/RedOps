"use client";

import { useEffect, useMemo, useRef, useState } from "react";

type ToolRun = {
  id: string;
  tool: string;
  status: string;
  attempt: number;
  queued_at?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  duration_ms?: number | null;
  exit_code?: number | null;
  short_error?: string | null;
  stderr_path?: string | null;
  stdout_path?: string | null;
  artifact_path?: string | null;
  metadata?: unknown;
};

type ScanBundle = {
  scan?: { id: string; status: string; target: string; created_at: string };
  tool_runs?: ToolRun[];
  findings?: unknown[];
  error?: string;
};

function asRecord(v: unknown): Record<string, unknown> | null {
  if (!v || typeof v !== "object") return null;
  return v as Record<string, unknown>;
}

function getNumber(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string") {
    const s = v.trim().replace(/%$/, "");
    const n = Number(s);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

function statusPill(status: string): { text: string; className: string } {
  const s = (status || "").toLowerCase();
  if (s === "success" || s === "done" || s === "completed") return { text: status, className: "pill success" };
  if (s === "failed" || s === "timeout") return { text: status, className: "pill danger" };
  if (s === "queued" || s === "running") return { text: status, className: "pill accent" };
  return { text: status || "unknown", className: "pill" };
}

function percentForRun(r: ToolRun): number | null {
  const s = (r.status || "").toLowerCase();
  if (s === "success" || s === "done" || s === "completed") return 100;
  if (s === "failed" || s === "timeout" || s === "canceled") return 100;

  const meta = asRecord(r.metadata);
  const progress = asRecord(meta?.progress);
  const nucleiStats = asRecord(meta?.nuclei_stats);
  const p = getNumber(progress?.percent) ?? getNumber(nucleiStats?.percent);
  if (p === null) return null;
  return Math.max(0, Math.min(100, p));
}

export function ScanProgressClient({
  scanId,
  initialStatus,
  initialToolRuns,
}: {
  scanId: string;
  initialStatus: string;
  initialToolRuns: ToolRun[];
}) {
  const [open, setOpen] = useState(() => {
    const s = (initialStatus || "").toLowerCase();
    return s === "queued" || s === "running";
  });
  const [status, setStatus] = useState(initialStatus);
  const [toolRuns, setToolRuns] = useState<ToolRun[]>(initialToolRuns);
  const timerRef = useRef<number | null>(null);

  const isActive = useMemo(() => {
    const s = (status || "").toLowerCase();
    return s === "queued" || s === "running";
  }, [status]);

  useEffect(() => {
    if (!open) return;
    if (!isActive) return;

    async function poll() {
      try {
        const res = await fetch(`/api/scans/${encodeURIComponent(scanId)}/bundle`, { cache: "no-store" });
        const text = await res.text();
        if (!res.ok) return;
        const bundle = JSON.parse(text) as ScanBundle;
        if (bundle?.scan?.status) setStatus(bundle.scan.status);
        if (Array.isArray(bundle?.tool_runs)) setToolRuns(bundle.tool_runs);
      } catch {
        // ignore transient errors
      }
    }

    poll();
    timerRef.current = window.setInterval(poll, 1500);

    return () => {
      if (timerRef.current) window.clearInterval(timerRef.current);
      timerRef.current = null;
    };
  }, [open, isActive, scanId]);

  const tools = useMemo(() => {
    // Group by tool and pick the latest attempt for display.
    const latest = new Map<string, ToolRun>();
    for (const r of toolRuns || []) {
      const key = r.tool || "unknown";
      const prev = latest.get(key);
      if (!prev || (r.attempt ?? 0) >= (prev.attempt ?? 0)) latest.set(key, r);
    }
    return Array.from(latest.values()).sort((a, b) => (a.tool || "").localeCompare(b.tool || ""));
  }, [toolRuns]);

  const overall = useMemo(() => {
    const total = tools.length || 0;
    const done = tools.filter((t) => {
      const s = (t.status || "").toLowerCase();
      return s === "success" || s === "failed" || s === "timeout" || s === "canceled";
    }).length;
    const pct = total ? Math.round((done / total) * 100) : 0;
    return { total, done, pct };
  }, [tools]);

  if (!open) {
    return (
      <button className="btn" type="button" onClick={() => setOpen(true)}>
        Live progress
      </button>
    );
  }

  return (
    <>
      <button className="btn" type="button" onClick={() => setOpen(true)} style={{ display: "none" }}>
        Live progress
      </button>
      <div className="modalOverlay" onMouseDown={() => setOpen(false)}>
        <div
          className="modal"
          role="dialog"
          aria-modal="true"
          aria-label="Scan progress"
          onMouseDown={(e) => e.stopPropagation()}
          style={{ maxWidth: 860 }}
        >
          <div className="modalHeader">
            <div>
              <div className="modalTitle">Scan progress</div>
              <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>
                Status: {status || "unknown"} • Tools done: {overall.done}/{overall.total}
              </div>
            </div>
            <div className="modalActions">
              <button className="btn" type="button" onClick={() => setOpen(false)}>
                Close
              </button>
            </div>
          </div>

          <div className="modalBody">
            <div style={{ marginBottom: 12 }}>
              <div className="muted" style={{ fontSize: 12, marginBottom: 6 }}>
                Overall
              </div>
              <div style={{ height: 10, borderRadius: 999, border: "1px solid var(--border)", overflow: "hidden" }}>
                <div
                  style={{
                    width: `${overall.pct}%`,
                    height: "100%",
                    background: "rgba(122, 162, 255, 0.35)",
                  }}
                />
              </div>
            </div>

            {tools.length === 0 ? (
              <div className="muted">Waiting for worker to start tools…</div>
            ) : (
              <div className="stack" style={{ gap: 10 }}>
                {tools.map((r) => {
                  const pct = percentForRun(r);
                  const pill = statusPill(r.status);
                  return (
                    <div
                      key={r.tool}
                      className="card"
                      style={{ padding: 12, borderRadius: 12, background: "rgba(255,255,255,0.03)" }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "baseline" }}>
                        <div style={{ fontWeight: 650 }}>{r.tool}</div>
                        <span className={pill.className}>{pill.text}</span>
                      </div>
                      <div style={{ marginTop: 8 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                          <div className="muted" style={{ fontSize: 12 }}>
                            {pct === null ? "Working…" : `${pct.toFixed(0)}%`}
                          </div>
                          <div className="muted" style={{ fontSize: 12 }}>
                            attempt {r.attempt}
                          </div>
                        </div>
                        <div style={{ height: 10, borderRadius: 999, border: "1px solid var(--border)", overflow: "hidden", marginTop: 6 }}>
                          {pct === null ? (
                            <div
                              style={{
                                width: "40%",
                                height: "100%",
                                background: "rgba(122, 162, 255, 0.22)",
                                animation: "scanIndeterminate 1.2s ease-in-out infinite alternate",
                              }}
                            />
                          ) : (
                            <div
                              style={{
                                width: `${pct}%`,
                                height: "100%",
                                background:
                                  (r.status || "").toLowerCase() === "failed" || (r.status || "").toLowerCase() === "timeout"
                                    ? "rgba(255, 107, 107, 0.35)"
                                    : "rgba(122, 162, 255, 0.35)",
                              }}
                            />
                          )}
                        </div>
                        {r.short_error ? (
                          <div className="help error" style={{ marginTop: 8 }}>
                            {r.short_error}
                          </div>
                        ) : null}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>

      <style jsx global>{`
        @keyframes scanIndeterminate {
          from { transform: translateX(0); }
          to { transform: translateX(140%); }
        }
      `}</style>
    </>
  );
}
