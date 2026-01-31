import { NextResponse } from "next/server";

import { apiFetch } from "@/lib/api";

export async function POST(req: Request) {
  const payload = await req.json().catch(() => ({}));
  const res = await apiFetch(`/scan`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  const body = await res.text();
  return new NextResponse(body, {
    status: res.status,
    headers: {
      "content-type": res.headers.get("content-type") || "application/json",
    },
  });
}
