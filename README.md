# AI Red Team Operator (MVP)

Minimal backend + worker for running security tooling pipelines.

## Safety gates (scope control)

Built-in scope controls to prevent accidental unauthorized scanning.

### Required: explicit allowlist

Scans are rejected unless the target host matches `SCAN_ALLOWLIST`.

- Set `SCAN_ALLOWLIST` to a comma/space/newline-separated list of allowed items.
- Items can be domains (subdomains allowed), CIDRs, or lab service names.

Examples:

- `SCAN_ALLOWLIST=example.com,1.2.3.0/24`
- `SCAN_ALLOWLIST=juiceshop,host.docker.internal`

Domain matching rules:

- `example.com` allows `example.com` and `*.example.com`
- `*.example.com` / `.example.com` allows subdomains (and `example.com`)

### Private IPs blocked by default

Targets that are private/local (e.g., `10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`, `::1`, `fc00::/7`, link-local) are blocked by default.

Override only for lab environments:

- `LAB_MODE=1`

### Per-scan rate limiting (basic)

The worker enforces a simple per-scan concurrency cap by clamping common tool args (e.g. `concurrency`).

- `SCAN_CONCURRENCY_CAP=10`
- You can also provide `concurrency_cap` in the `/scan` request body to persist it per scan.

### Provenance

Each scan stores who triggered it via `triggered_by` and which API key was used via `api_key_id`.

- Provide `X-Triggered-By: local` (or a username) header, or `triggered_by` in the request body.

### API auth (required for /scan)

`POST /scan` requires an API key.

- Configure `API_KEYS` as a comma/space/newline-separated list of `<id>=<secret>` entries.
- Send the secret via either `Authorization: Bearer <secret>` or `X-API-Key: <secret>`.

## Quick start

Note (Linux): if you see `permission denied while trying to connect to the Docker daemon socket`, run compose with `sudo` (e.g. `sudo docker compose up --build`) or add your user to the `docker` group and re-login.

1. Set env vars (at minimum):

	- `SCAN_ALLOWLIST=juiceshop,host.docker.internal`
	- `LAB_MODE=1`
	- `API_KEYS=local=changeme`

2. Start services:

	- `docker compose up --build`

3. Create a scan:

	- `curl -s -X POST http://localhost:8000/scan -H 'Content-Type: application/json' -H 'Authorization: Bearer changeme' -H 'X-Triggered-By: local' -d '{"target":"http://juiceshop:3000","concurrency_cap":10}' | jq`

4. Watch progress (optional):

	- `curl -s http://localhost:8000/scan/<scan_id> | jq`

5. Get reports:

	- JSON summary: `curl -s http://localhost:8000/scans/<scan_id>/summary | jq`
	- Markdown report: `curl -s http://localhost:8000/scans/<scan_id>/report.md`

You can also browse the API in the FastAPI docs:

- Swagger UI: `http://localhost:8000/docs`
- OpenAPI JSON: `http://localhost:8000/openapi.json`

## Frontend (Next.js MVP)

The project includes a minimal web UI under `frontend/`.

### Configure

Set these environment variables (recommended via `frontend/.env.local`):

- `NEXT_PUBLIC_API_BASE_URL` (example: `http://localhost:8000`)
- `API_KEY` (example: `changeme`)

When running via Docker Compose, the frontend container uses:

- `BACKEND_URL` (default: `http://backend:8000`)

Notes:

- The UI proxies requests through Next.js route handlers (e.g. `/api/scans/...`) so the API key is not required in the browser.
- Backend must be configured with a matching `API_KEYS` entry.

### Run locally

```bash
cd frontend
npm install
API_KEY=changeme NEXT_PUBLIC_API_BASE_URL=http://localhost:8000 npm run dev
```

Then open `http://localhost:3000`.

