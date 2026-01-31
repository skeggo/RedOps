"use client";

import { useMemo, useState } from "react";
import { JsonModal } from "@/components/JsonModal";

export type FindingRow = {
  tool: string;
  fingerprint?: string | null;
  created_at?: string | null;
  payload: unknown;
  asset_host?: string | null;
  asset_port?: number | null;
  asset_scheme?: string | null;
  endpoint_url?: string | null;
  endpoint_method?: string | null;
  endpoint_status?: number | null;
  endpoint_title?: string | null;
  endpoint_source?: string | null;
  mitre?: Array<{
    technique_id: string;
    name?: string | null;
    tactic?: string | null;
    tactics?: Array<{ tactic_id: string; shortname: string; name: string }>;
    confidence?: number | null;
    reason?: string | null;
    source?: string | null;
  }>;
};

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString();
}

function safeString(v: unknown): string {
  if (v === null || v === undefined) return "";
  return typeof v === "string" ? v : String(v);
}

function prettyJson(v: unknown): string {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return safeString(v);
  }
}

function asRecord(v: unknown): Record<string, unknown> | null {
  if (!v || typeof v !== "object") return null;
  return v as Record<string, unknown>;
}

function getStr(obj: Record<string, unknown> | null, key: string): string {
  if (!obj) return "";
  const v = obj[key];
  return typeof v === "string" ? v : v === null || v === undefined ? "" : String(v);
}

function extractSummary(f: FindingRow): { title: string; severity?: string; where?: string } {
  const tool = (f.tool || "").toLowerCase();
  const p = asRecord(f.payload);

  if (tool === "nuclei" && p) {
    const title =
      getStr(p, "title") ||
      getStr(p, "name") ||
      getStr(p, "template-id") ||
      getStr(p, "template_id") ||
      "nuclei finding";
    const severity = getStr(p, "severity").toLowerCase() || undefined;
    const where =
      (getStr(p, "matched_at") || getStr(p, "matched-at") || getStr(p, "host")).trim() || undefined;
    return { title, severity, where };
  }

  if (tool === "httpx" && p) {
    const title = getStr(p, "title") || getStr(p, "webserver") || "httpx result";
    const where = (getStr(p, "url") || getStr(p, "host")).trim() || undefined;
    return { title, where };
  }

  if (tool === "katana" && p) {
    const count = p["count"] ?? p["urls_count"];
    const title = typeof count === "number" ? `katana urls (${count})` : "katana";
    return { title };
  }

  const title = tool ? tool : "finding";
  return { title };
}

function sevPill(sev?: string): React.ReactNode {
  if (!sev) return null;
  const s = sev.toLowerCase();
  const cls =
    s === "critical" || s === "high"
      ? "pill danger"
      : s === "medium"
        ? "pill accent"
        : "pill";
  return (
    <span className={cls} style={{ marginLeft: 8 }}>
      {s}
    </span>
  );
}

export function FindingsTableClient({ findings }: { findings: FindingRow[] }) {
  const [q, setQ] = useState("");
  const [modal, setModal] = useState<{ title: string; content: string } | null>(null);

  const filtered = useMemo(() => {
    const query = q.trim().toLowerCase();
    if (!query) return findings;
    return findings.filter((f) => {
      const hay = [
        f.tool,
        f.fingerprint,
        f.endpoint_url,
        f.endpoint_method,
        f.endpoint_title,
        f.asset_host,
        prettyJson(f.payload),
        (f.mitre || []).map((t) => `${t.technique_id} ${t.name || ""} ${t.tactic || ""}`).join(" "),
      ]
        .filter(Boolean)
        .join("\n")
        .toLowerCase();
      return hay.includes(query);
    });
  }, [findings, q]);

  return (
    <div>
      <div className="row" style={{ marginBottom: 12 }}>
        <div>
          <div className="pageTitle">Findings</div>
          <div className="muted">Search across tool, endpoint, payload, and MITRE.</div>
        </div>
        <div style={{ display: "flex", justifyContent: "flex-end", alignItems: "flex-end" }}>
          <input
            className="input"
            placeholder="Search…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            style={{ maxWidth: 420 }}
          />
        </div>
      </div>

      <div className="card">
        <div className="tableScroll">
          <table className="table" style={{ minWidth: 980 }}>
          <thead>
            <tr>
              <th>When</th>
              <th>Tool</th>
              <th>Summary</th>
              <th>Endpoint</th>
              <th>MITRE</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className="muted">
                  No matches.
                </td>
              </tr>
            ) : (
              filtered.map((f, i) => {
                const s = extractSummary(f);
                const endpoint = `${(f.endpoint_method || "").toUpperCase()} ${f.endpoint_url || ""}`.trim();
                const mitreIds = (f.mitre || []).map((t) => t.technique_id).filter(Boolean);

                return (
                  <tr key={`${f.tool}-${f.fingerprint ?? i}`}
                    >
                    <td style={{ whiteSpace: "nowrap" }}>{formatDate(f.created_at)}</td>
                    <td>
                      {f.tool}
                      {sevPill(s.severity)}
                    </td>
                    <td style={{ maxWidth: 420 }}>
                      <div style={{ fontWeight: 600 }}>{s.title}</div>
                      <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                        {s.where || f.asset_host || ""}
                      </div>
                      {f.fingerprint ? (
                        <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                          fp: {f.fingerprint}
                        </div>
                      ) : null}
                    </td>
                    <td className="muted" style={{ maxWidth: 420 }}>
                      {endpoint || "—"}
                      {f.endpoint_title ? (
                        <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                          {f.endpoint_title}
                        </div>
                      ) : null}
                    </td>
                    <td className="muted" style={{ maxWidth: 260 }}>
                      {mitreIds.length ? mitreIds.join(", ") : "—"}
                    </td>
                    <td style={{ maxWidth: 520 }}>
                      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                        <button
                          className="btn"
                          type="button"
                          onClick={() => setModal({ title: "Payload", content: prettyJson(f.payload) })}
                        >
                          Payload
                        </button>
                        <button
                          className="btn"
                          type="button"
                          disabled={!(f.mitre || []).length}
                          onClick={() => setModal({ title: "MITRE mapping", content: prettyJson(f.mitre) })}
                        >
                          MITRE
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
          </table>
        </div>
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
