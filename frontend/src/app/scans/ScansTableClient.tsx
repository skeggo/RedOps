"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";

export type ScanListItem = {
  id: string;
  target: string;
  status: string;
  created_at: string;
  findings_count: number | null;
};

type ApiError = {
  detail?: string;
  error?: string;
};

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString();
}

function statusClass(status: string): string {
  const s = (status || "").toLowerCase();
  if (s === "completed" || s === "done") return "pill success";
  if (s === "failed" || s === "timeout") return "pill danger";
  if (s === "queued" || s === "running") return "pill accent";
  return "pill";
}

export function ScansTableClient({ scans }: { scans: ScanListItem[] }) {
  const router = useRouter();
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedIds = useMemo(() => Object.keys(selected).filter((id) => selected[id]), [selected]);
  const allSelected = useMemo(
    () => scans.length > 0 && scans.every((s) => selected[s.id]),
    [scans, selected]
  );
  const anySelected = selectedIds.length > 0;

  function toggleAll(next: boolean) {
    const m: Record<string, boolean> = {};
    for (const s of scans) m[s.id] = next;
    setSelected(m);
  }

  function toggleOne(id: string, next: boolean) {
    setSelected((prev) => ({ ...prev, [id]: next }));
  }

  async function bulkDelete() {
    setError(null);
    if (!anySelected) return;

    const ok = window.confirm(`Delete ${selectedIds.length} scan(s) and all associated data?`);
    if (!ok) return;

    setDeleting(true);
    try {
      const results = await Promise.allSettled(
        selectedIds.map(async (id) => {
          const res = await fetch(`/api/scans/${encodeURIComponent(id)}`, { method: "DELETE" });
          const text = await res.text();
          if (!res.ok) {
            let msg = text;
            try {
              const j = JSON.parse(text) as ApiError;
              msg = j.detail || j.error || text;
            } catch {
              // ignore
            }
            throw new Error(`${id}: ${msg || `Delete failed (${res.status})`}`);
          }
        })
      );

      const failures = results
        .filter((r): r is PromiseRejectedResult => r.status === "rejected")
        .map((r) => (r.reason instanceof Error ? r.reason.message : String(r.reason)));

      if (failures.length) {
        setError(failures.slice(0, 5).join("\n"));
      } else {
        setSelected({});
      }

      router.refresh();
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div>
      <div className="row" style={{ marginBottom: 12 }}>
        <div>
          <div className="pageTitle">Scans</div>
          <div className="muted">Newest first. Select scans to delete in bulk.</div>
        </div>
        <div
          style={{
            display: "flex",
            justifyContent: "flex-end",
            alignItems: "flex-end",
            gap: 10,
            flexWrap: "wrap",
          }}
        >
          <button className="btn" disabled={!anySelected || deleting} onClick={bulkDelete}>
            {deleting ? "Deleting…" : `Delete selected (${selectedIds.length})`}
          </button>
          <Link className="btn primary" href="/scans/new">
            Create scan
          </Link>
        </div>
      </div>

      {error ? (
        <pre className="help error" style={{ whiteSpace: "pre-wrap", marginBottom: 12 }}>
          {error}
        </pre>
      ) : null}

      <table className="table">
        <thead>
          <tr>
            <th style={{ width: 44 }}>
              <input
                type="checkbox"
                checked={allSelected}
                onChange={(e) => toggleAll(e.target.checked)}
                aria-label="Select all"
              />
            </th>
            <th>Target</th>
            <th>Status</th>
            <th>Created</th>
            <th>Findings</th>
          </tr>
        </thead>
        <tbody>
          {scans.length === 0 ? (
            <tr>
              <td colSpan={5} className="muted">
                No scans yet. Create one.
              </td>
            </tr>
          ) : (
            scans.map((s) => (
              <tr key={s.id}>
                <td>
                  <input
                    type="checkbox"
                    checked={!!selected[s.id]}
                    onChange={(e) => toggleOne(s.id, e.target.checked)}
                    aria-label={`Select ${s.id}`}
                  />
                </td>
                <td>
                  <Link href={`/scans/${encodeURIComponent(s.id)}`}>{s.target}</Link>
                  <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                    {s.id}
                  </div>
                </td>
                <td>
                  <span className={statusClass(s.status)}>{s.status}</span>
                </td>
                <td>{formatDate(s.created_at)}</td>
                <td>{s.findings_count ?? "—"}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
