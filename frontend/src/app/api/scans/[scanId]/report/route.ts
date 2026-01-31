import { NextResponse } from "next/server";

import { apiFetch } from "@/lib/api";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ scanId: string }> }
) {
  const { scanId } = await params;

  const res = await apiFetch(`/scans/${encodeURIComponent(scanId)}/report.md`, {
    headers: {
      Accept: "text/markdown",
    },
  });

  const body = await res.arrayBuffer();
  const filename = `scan-${scanId}.report.md`;
  return new NextResponse(body, {
    status: res.status,
    headers: {
      "content-type": res.headers.get("content-type") || "text/markdown; charset=utf-8",
      "content-disposition": `attachment; filename=\"${filename}\"`,
    },
  });
}
