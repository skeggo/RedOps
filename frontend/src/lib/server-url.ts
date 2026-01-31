import { headers } from "next/headers";

export async function getSelfBaseUrl(): Promise<string> {
  const h = await headers();
  const host = h.get("x-forwarded-host") || h.get("host");
  const proto = h.get("x-forwarded-proto") || "http";

  if (!host) {
    // Dev fallback: Next dev always has a host, but keep a safe default.
    return "http://localhost:3000";
  }

  return `${proto}://${host}`;
}
