import { NextResponse } from "next/server";

import { apiFetch } from "@/lib/api";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const limit = url.searchParams.get("limit") || "50";
  const offset = url.searchParams.get("offset") || "0";
  const status = url.searchParams.get("status");

  const qs = new URLSearchParams({ limit, offset });
  if (status) qs.set("status", status);

  const res = await apiFetch(`/scans?${qs.toString()}`);
  const body = await res.text();
  return new NextResponse(body, {
    status: res.status,
    headers: {
      "content-type": res.headers.get("content-type") || "application/json",
    },
  });
}
