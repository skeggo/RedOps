import Link from "next/link";
import { getSelfBaseUrl } from "@/lib/server-url";

type ScanRow = {
  id: string;
  target: string;
  status: string;
  created_at: string;
};

type ScansResponse = {
  scans: ScanRow[];
  limit: number;
  offset: number;
  status: string | null;
};

type SummaryResponse = {
  counts?: {
    findings_total?: number;
  };
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

async function fetchScans(baseUrl: string): Promise<ScanRow[]> {
  const res = await fetch(`${baseUrl}/api/scans?limit=50&offset=0`, { cache: "no-store" });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Failed to load scans (${res.status})`);
  }
  const data = (await res.json()) as ScansResponse;
  return data.scans || [];
}

async function fetchFindingCount(baseUrl: string, scanId: string): Promise<number | null> {
  const res = await fetch(`${baseUrl}/api/scans/${encodeURIComponent(scanId)}/summary`, {
    cache: "no-store",
  });
  if (!res.ok) return null;
  const data = (await res.json()) as SummaryResponse;
  const n = data?.counts?.findings_total;
  return typeof n === "number" ? n : null;
}

export default async function ScansPage() {
  const baseUrl = await getSelfBaseUrl();
  const scans = await fetchScans(baseUrl);
  const counts = await Promise.all(scans.map((s) => fetchFindingCount(baseUrl, s.id)));

  return (
    <div>
      <div className="row" style={{ marginBottom: 12 }}>
        <div>
          <div className="pageTitle">Scans</div>
          <div className="muted">Newest first. Click a scan for details.</div>
        </div>
        <div style={{ display: "flex", justifyContent: "flex-end", alignItems: "flex-end" }}>
          <Link className="btn primary" href="/scans/new">
            Create scan
          </Link>
        </div>
      </div>

      <table className="table">
        <thead>
          <tr>
            <th>Target</th>
            <th>Status</th>
            <th>Created</th>
            <th>Findings</th>
          </tr>
        </thead>
        <tbody>
          {scans.length === 0 ? (
            <tr>
              <td colSpan={4} className="muted">
                No scans yet. Create one.
              </td>
            </tr>
          ) : (
            scans.map((s, idx) => (
              <tr key={s.id}>
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
                <td>{counts[idx] ?? "—"}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
