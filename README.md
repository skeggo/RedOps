AI Red Team Operator (MVP)

Purpose
- Small framework for automated red-team style scans: recon, HTTP probing, vulnerability scanners.

Quickstart (local, Docker)

1. Copy `.env.example` to `.env` and set any secrets locally (do NOT commit `.env`).

2. Build & run with Docker Compose:

```sh
sudo docker compose up --build
```

3. Start a scan (HTTP API):

```sh
curl -X POST -H "Content-Type: application/json" -d '{"target":"example.com"}' http://localhost:8000/scan
```

4. Check results:

```sh
curl http://localhost:8000/scan/<scan_id>
```

Design
- Worker uses a plugin model: `worker/tools/*.py` implement a small `can_run(ctx)` / `run(ctx, timeout, args)` interface.
- Pipelines are YAML files under `worker/pipelines/*.yml` that declare ordered tools and per-tool args.
- `worker/install-tools.sh` + `worker/tools.yaml` is used at image build to install third-party binaries into the worker image.

Adding tools
- Add a new plugin file to `worker/tools/` implementing `NAME`, `can_run`, and `run`.
- Add a pipeline entry in `worker/pipelines/*.yml` (or create a new pipeline) to include the tool and its args.
- To add a binary tool in the image, add an entry to `worker/tools.yaml` and rebuild the worker image.

Security & legal
- This project includes offensive-security tooling. Only use it against systems you own or have explicit authorization to test.
- Do NOT publish secrets (DB passwords, API keys). Move secrets into `.env` and exclude it via `.gitignore`.

Next steps
- Add a `SECURITY.md` and `CONTRIBUTING.md` (included).
- Consider adding CI to build images and run linting.

# RedOps