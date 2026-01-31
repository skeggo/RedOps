"use client";

import Link from "next/link";
import { useState } from "react";

import { JsonModal } from "@/components/JsonModal";

type FindingRow = {
  tool: string;
  fingerprint?: string | null;
  created_at?: string | null;
  payload: unknown;
  endpoint_url?: string | null;
  endpoint_method?: string | null;
};

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString();
}

function prettyJson(v: unknown): string {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

export function FindingsPreviewClient({
  scanId,
  findings,
  totalCount,
}: {
  scanId: string;
  findings: FindingRow[];
  totalCount: number;
}) {
  const [modal, setModal] = useState<{ title: string; content: string } | null>(null);

  return (
    <div className="card">
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "baseline",
          gap: 12,
          marginBottom: 8,
        }}
      >
        <div style={{ fontWeight: 650 }}>Findings ({totalCount})</div>
        <Link className="btn" href={`/scans/${encodeURIComponent(scanId)}/findings`}>
          Details
        </Link>
      </div>

      <div className="tableScroll" style={{ maxHeight: 420 }}>
        <table className="table" style={{ minWidth: 900 }}>
          <thead>
            <tr>
              <th>Tool</th>
              <th>When</th>
              <th>Endpoint</th>
              <th>Summary</th>
            </tr>
          </thead>
          <tbody>
            {findings.length === 0 ? (
              <tr>
                <td colSpan={4} className="muted">
                  No findings yet.
                </td>
              </tr>
            ) : (
              findings.map((f, i) => (
                <tr key={`${f.tool}-${f.fingerprint ?? i}`}>
                  <td>{f.tool}</td>
                  <td style={{ whiteSpace: "nowrap" }}>{formatDate(f.created_at)}</td>
                  <td className="muted" style={{ maxWidth: 520 }}>
                    {`${(f.endpoint_method || "").toUpperCase()} ${f.endpoint_url || ""}`.trim() || "—"}
                  </td>
                  <td>
                    <button
                      className="btn"
                      type="button"
                      onClick={() => {
                        const fp = f.fingerprint ? `fingerprint: ${f.fingerprint}\n\n` : "";
                        setModal({ title: "Summary", content: fp + prettyJson(f.payload) });
                      }}
                    >
                      Open
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <JsonModal
        open={!!modal}
        title={modal?.title || ""}
        content={modal?.content || ""}
        onClose={() => setModal(null)}
      />
    </div>
  );
}
