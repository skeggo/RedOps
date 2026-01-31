import { NextResponse } from "next/server";

import { apiFetch } from "@/lib/api";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ scanId: string }> }
) {
  const { scanId } = await params;
  const res = await apiFetch(`/scan/${encodeURIComponent(scanId)}`);
  const body = await res.text();
  return new NextResponse(body, {
    status: res.status,
    headers: {
      "content-type": res.headers.get("content-type") || "application/json",
    },
  });
}
