import Link from "next/link";
import { getSelfBaseUrl } from "@/lib/server-url";
import { DeleteScanButton } from "./DeleteScanButton";
import { FindingsPreviewClient } from "./FindingsPreviewClient";
import { ScanProgressClient } from "./ScanProgressClient";

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
  stdout_path?: string | null;
  stderr_path?: string | null;
  artifact_path?: string | null;
  metadata?: unknown;
};

type Finding = {
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

type ScanBundle = {
  scan?: {
    id: string;
    target: string;
    status: string;
    created_at: string;
    triggered_by?: string;
    api_key_id?: string;
  };
  tool_runs?: ToolRun[];
  findings?: Finding[];
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

export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ scanId: string }>;
}) {
  const { scanId } = await params;

  const baseUrl = await getSelfBaseUrl();

  const res = await fetch(`${baseUrl}/api/scans/${encodeURIComponent(scanId)}/bundle`, {
    cache: "no-store",
  });
  const text = await res.text();
  if (!res.ok) {
    return (
      <div>
        <div className="pageTitle">Scan</div>
        <div className="help error">Failed to load scan: {text}</div>
      </div>
    );
  }

  const bundle = JSON.parse(text) as ScanBundle;
  if (bundle?.error) {
    return (
      <div>
        <div className="pageTitle">Scan</div>
        <div className="help error">{bundle.error}</div>
      </div>
    );
  }

  const scan = bundle.scan;
  const toolRuns = bundle.tool_runs || [];
  const findings = bundle.findings || [];

  const assets = Array.from(
    new Map(
      findings
        .filter((f) => f.asset_host)
        .map((f) => {
          const key = `${f.asset_scheme || ""}://${f.asset_host || ""}:${f.asset_port ?? ""}`;
          return [key, {
            host: f.asset_host || "",
            port: f.asset_port ?? null,
            scheme: f.asset_scheme ?? null,
          }] as const;
        })
    ).values()
  );

  const endpoints = Array.from(
    new Map(
      findings
        .filter((f) => f.endpoint_url)
        .map((f) => {
          const key = `${f.endpoint_method || ""} ${f.endpoint_url || ""}`.trim();
          return [key, {
            url: f.endpoint_url || "",
            method: f.endpoint_method || "",
            status: f.endpoint_status ?? null,
            title: f.endpoint_title ?? null,
            source: f.endpoint_source ?? null,
          }] as const;
        })
    ).values()
  );

  const techniques = new Map<
    string,
    {
      technique_id: string;
      name: string | null;
      tactics: string[];
      max_confidence: number | null;
      count: number;
    }
  >();

  for (const f of findings) {
    for (const t of f.mitre || []) {
      const id = t.technique_id;
      if (!id) continue;
      const tactics = (t.tactics || []).map((x) => x.shortname || x.name).filter(Boolean) as string[];
      if (!tactics.length && t.tactic) tactics.push(t.tactic);
      const existing = techniques.get(id);
      const conf = typeof t.confidence === "number" ? t.confidence : null;
      if (!existing) {
        techniques.set(id, {
          technique_id: id,
          name: (t.name || null) as string | null,
          tactics: Array.from(new Set(tactics)),
          max_confidence: conf,
          count: 1,
        });
      } else {
        existing.count += 1;
        existing.name = existing.name || ((t.name || null) as string | null);
        existing.tactics = Array.from(new Set([...existing.tactics, ...tactics]));
        if (conf !== null) {
          existing.max_confidence =
            existing.max_confidence === null ? conf : Math.max(existing.max_confidence, conf);
        }
      }
    }
  }

  const techniqueRows = Array.from(techniques.values()).sort((a, b) => {
    const ac = a.max_confidence ?? -1;
    const bc = b.max_confidence ?? -1;
    if (bc !== ac) return bc - ac;
    return a.technique_id.localeCompare(b.technique_id);
  });

  return (
    <div>
      <div className="row" style={{ marginBottom: 12 }}>
        <div>
          <div className="pageTitle">Scan detail</div>
          <div className="muted">
            {scan?.target || scanId} • <span className={statusClass(scan?.status || "unknown")}>{scan?.status || "unknown"}</span>
          </div>
          <div className="help">
            Created: {formatDate(scan?.created_at)}
            {scan?.triggered_by ? ` • by ${scan.triggered_by}` : ""}
          </div>
        </div>
        <div style={{ display: "flex", justifyContent: "flex-end", alignItems: "flex-end", gap: 10 }}>
          <Link className="btn" href="/scans">
            Back
          </Link>
          <ScanProgressClient scanId={scanId} initialStatus={scan?.status || "unknown"} initialToolRuns={toolRuns} />
          <DeleteScanButton scanId={scanId} />
          <a className="btn primary" href={`/api/scans/${encodeURIComponent(scanId)}/report`}>
            Download report.md
          </a>
        </div>
      </div>

      <div className="stack">
        <div className="card" style={{ overflowX: "auto" }}>
          <div style={{ fontWeight: 650, marginBottom: 8 }}>Tool runs</div>
          <table className="table">
            <thead>
              <tr>
                <th>Tool</th>
                <th>Status</th>
                <th>Attempt</th>
                <th>Queued</th>
                <th>Started</th>
                <th>Finished</th>
                <th>Duration</th>
              </tr>
            </thead>
            <tbody>
              {toolRuns.length === 0 ? (
                <tr>
                  <td colSpan={7} className="muted">
                    No tool runs yet.
                  </td>
                </tr>
              ) : (
                toolRuns.map((r) => (
                  <tr key={r.id}>
                    <td>{r.tool}</td>
                    <td>
                      <span className={statusClass(r.status)}>{r.status}</span>
                      {r.short_error ? (
                        <div className="help error" style={{ marginTop: 4 }}>
                          {r.short_error}
                        </div>
                      ) : null}
                    </td>
                    <td>{r.attempt}</td>
                    <td>{formatDate(r.queued_at)}</td>
                    <td>{formatDate(r.started_at)}</td>
                    <td>{formatDate(r.finished_at)}</td>
                    <td>{typeof r.duration_ms === "number" ? `${r.duration_ms}ms` : "—"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="card">
          <div style={{ fontWeight: 650, marginBottom: 8 }}>Assets & endpoints</div>
          <div className="help">Derived from stored findings (no extra backend endpoints required).</div>
          <div style={{ marginTop: 10 }}>
            <div className="muted" style={{ marginBottom: 6 }}>
              Assets ({assets.length})
            </div>
            <ul style={{ paddingLeft: 18 }}>
              {assets.slice(0, 30).map((a) => (
                <li key={`${a.scheme}:${a.host}:${a.port}`}>{`${a.scheme || ""}://${a.host}${a.port ? `:${a.port}` : ""}`}</li>
              ))}
              {assets.length > 30 ? <li className="muted">…and {assets.length - 30} more</li> : null}
            </ul>
          </div>
          <div style={{ marginTop: 12 }}>
            <div className="muted" style={{ marginBottom: 6 }}>
              Endpoints ({endpoints.length})
            </div>
            <ul style={{ paddingLeft: 18 }}>
              {endpoints.slice(0, 30).map((e) => (
                <li key={`${e.method} ${e.url}`}>{`${e.method || ""} ${e.url}`.trim()}</li>
              ))}
              {endpoints.length > 30 ? <li className="muted">…and {endpoints.length - 30} more</li> : null}
            </ul>
          </div>
        </div>
      </div>

      <div className="stack" style={{ marginTop: 12 }}>
        <FindingsPreviewClient
          scanId={scanId}
          totalCount={findings.length}
          findings={findings.map((f) => ({
            tool: f.tool,
            fingerprint: f.fingerprint,
            created_at: f.created_at,
            payload: f.payload,
            endpoint_method: f.endpoint_method,
            endpoint_url: f.endpoint_url,
          }))}
        />

        <div className="card" style={{ overflowX: "auto" }}>
          <div style={{ fontWeight: 650, marginBottom: 8 }}>MITRE techniques ({techniqueRows.length})</div>
          <table className="table">
            <thead>
              <tr>
                <th>Technique</th>
                <th>Name</th>
                <th>Tactics</th>
                <th>Max confidence</th>
                <th>Mentions</th>
              </tr>
            </thead>
            <tbody>
              {techniqueRows.length === 0 ? (
                <tr>
                  <td colSpan={5} className="muted">
                    No MITRE mappings yet.
                  </td>
                </tr>
              ) : (
                techniqueRows.map((t) => (
                  <tr key={t.technique_id}>
                    <td>{t.technique_id}</td>
                    <td>{t.name || "—"}</td>
                    <td className="muted">{t.tactics.join(", ") || "—"}</td>
                    <td className="muted">
                      {t.max_confidence === null ? "—" : t.max_confidence.toFixed(2)}
                    </td>
                    <td>{t.count}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
