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

1. Set env vars (at minimum):

	- `SCAN_ALLOWLIST=juiceshop`
	- `LAB_MODE=1`
	- `API_KEYS=local=changeme`

2. Start services:

	- `docker compose up --build`

3. Create a scan:

	- `curl -s -X POST http://localhost:8000/scan -H 'Content-Type: application/json' -H 'Authorization: Bearer changeme' -H 'X-Triggered-By: local' -d '{"target":"http://juiceshop:3000","concurrency_cap":10}' | jq`

