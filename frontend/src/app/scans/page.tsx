import { getSelfBaseUrl } from "@/lib/server-url";
import { ScansTableClient, type ScanListItem } from "./ScansTableClient";

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

  const rows: ScanListItem[] = scans.map((s, idx) => ({
    id: s.id,
    target: s.target,
    status: s.status,
    created_at: s.created_at,
    findings_count: counts[idx] ?? null,
  }));

  return <ScansTableClient scans={rows} />;
}
