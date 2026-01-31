export type ApiConfig = {
  baseUrl: string;
  apiKey: string | null;
};

export function getApiConfig(): ApiConfig {
  // In Compose/containers, the backend is usually reachable via the service DNS name.
  // Keep this server-only so we don't leak internal URLs to the browser.
  const serverBase = (process.env.BACKEND_URL || "").trim();
  const publicBase = (process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000").trim();

  const baseUrl = (serverBase || publicBase).replace(/\/$/, "");

  const apiKey = (process.env.API_KEY || process.env.NEXT_PUBLIC_API_KEY || "").trim();
  return { baseUrl, apiKey: apiKey ? apiKey : null };
}

export async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  const { baseUrl, apiKey } = getApiConfig();

  const url = path.startsWith("http") ? path : `${baseUrl}${path.startsWith("/") ? "" : "/"}${path}`;

  const headers = new Headers(init?.headers);
  if (apiKey) {
    headers.set("Authorization", `Bearer ${apiKey}`);
  }
  headers.set("Accept", headers.get("Accept") || "application/json");

  return fetch(url, {
    ...init,
    headers,
    cache: "no-store",
  });
}
