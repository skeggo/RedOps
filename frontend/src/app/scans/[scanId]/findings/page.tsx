import Link from "next/link";

import { getSelfBaseUrl } from "@/lib/server-url";
import { FindingsTableClient, type FindingRow } from "../FindingsTableClient";

type ScanBundle = {
  scan?: {
    id: string;
    target: string;
    status: string;
    created_at: string;
  };
  findings?: FindingRow[];
  error?: string;
};

export default async function ScanFindingsPage({
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
        <div className="pageTitle">Findings</div>
        <div className="help error">Failed to load scan: {text}</div>
      </div>
    );
  }

  const bundle = JSON.parse(text) as ScanBundle;
  if (bundle?.error) {
    return (
      <div>
        <div className="pageTitle">Findings</div>
        <div className="help error">{bundle.error}</div>
      </div>
    );
  }

  const findings = bundle.findings || [];

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
        <div className="muted" style={{ fontSize: 13 }}>
          Scan: <Link href={`/scans/${encodeURIComponent(scanId)}`}>{scanId}</Link>
        </div>
        <Link className="btn" href={`/scans/${encodeURIComponent(scanId)}`}>
          Back to scan
        </Link>
      </div>
      <FindingsTableClient findings={findings} />
    </div>
  );
}
