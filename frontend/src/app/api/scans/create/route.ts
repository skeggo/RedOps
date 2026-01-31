import { NextResponse } from "next/server";

import { apiFetch } from "@/lib/api";

export async function POST(req: Request) {
  const payload = await req.json().catch(() => ({}));
  const triggeredBy = req.headers.get("X-Triggered-By") || "local";
  const res = await apiFetch(`/scan`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-Triggered-By": triggeredBy,
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
