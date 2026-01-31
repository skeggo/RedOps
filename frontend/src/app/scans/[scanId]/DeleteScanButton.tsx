"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

type ApiError = {
  detail?: string;
  error?: string;
};

export function DeleteScanButton({ scanId }: { scanId: string }) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onDelete() {
    setError(null);

    const ok = window.confirm(
      "Delete this scan and all associated data (tool runs, findings, assets/endpoints)?"
    );
    if (!ok) return;

    setLoading(true);
    try {
      const res = await fetch(`/api/scans/${encodeURIComponent(scanId)}`, {
        method: "DELETE",
      });
      const text = await res.text();
      if (!res.ok) {
        let msg = text;
        try {
          const j = JSON.parse(text) as ApiError;
          msg = j.detail || j.error || text;
        } catch {
          // ignore
        }
        throw new Error(msg || `Delete failed (${res.status})`);
      }

      router.push("/scans");
      router.refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ display: "inline-flex", flexDirection: "column", alignItems: "flex-end" }}>
      <button className="btn" onClick={onDelete} disabled={loading}>
        {loading ? "Deleting…" : "Delete scan"}
      </button>
      {error ? (
        <div className="help error" style={{ marginTop: 8, maxWidth: 520, textAlign: "right" }}>
          {error}
        </div>
      ) : null}
    </div>
  );
}
