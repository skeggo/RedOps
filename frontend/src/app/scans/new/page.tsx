"use client";

import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import Link from "next/link";

type CreateScanOk = {
  scan_id: string;
  status: string;
  scope?: {
    host?: string;
    resolved_ips?: string[];
    warnings?: string[];
  };
};

type ApiError = {
  detail?: string;
  error?: string;
};

export default function NewScanPage() {
  const router = useRouter();
  const [target, setTarget] = useState("http://testphp.vulnweb.com");
  const [loading, setLoading] = useState(false);
  const [created, setCreated] = useState<CreateScanOk | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canSubmit = useMemo(() => target.trim().length > 0 && !loading, [target, loading]);

  function normalizeTarget(input: string): string {
    const t = input.trim();
    if (!t) return t;
    // If user enters a bare host (e.g., testphp.vulnweb.com), assume http://
    if (!/^https?:\/\//i.test(t)) return `http://${t}`;
    return t;
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setCreated(null);
    setLoading(true);
    try {
      const normalizedTarget = normalizeTarget(target);
      const res = await fetch("/api/scans/create", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          target: normalizedTarget,
          concurrency_cap: 10,
        }),
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
        throw new Error(msg || `Request failed (${res.status})`);
      }

      const data = JSON.parse(text) as CreateScanOk;
      setCreated(data);
      if (data.scan_id) {
        router.push(`/scans/${encodeURIComponent(data.scan_id)}`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <div className="pageTitle">Create scan</div>
      <div className="help">
        Scope is enforced by the backend allowlist. If your target is rejected you’ll see the reason here.
      </div>

      <div className="card" style={{ marginTop: 14 }}>
        <form onSubmit={onSubmit}>
          <label className="muted" style={{ display: "block", marginBottom: 8 }}>
            Target
          </label>
          <input
            className="input"
            placeholder="http://testphp.vulnweb.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            autoComplete="off"
          />
          <div style={{ display: "flex", gap: 10, marginTop: 12, alignItems: "center" }}>
            <button className="btn primary" type="submit" disabled={!canSubmit}>
              {loading ? "Creating…" : "Create scan"}
            </button>
            <Link className="btn" href="/scans">
              Cancel
            </Link>
          </div>
        </form>

        {error ? (
          <div className="help error" style={{ marginTop: 12 }}>
            {error}
          </div>
        ) : null}

        {created?.scope ? (
          <div style={{ marginTop: 12 }}>
            <div className="muted" style={{ marginBottom: 6 }}>
              Scope check
            </div>
            <div className="help">Host: {created.scope.host || "—"}</div>
            <div className="help">Resolved IPs: {(created.scope.resolved_ips || []).join(", ") || "—"}</div>
            <div className="help">
              Warnings: {(created.scope.warnings || []).join(", ") || "—"}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
