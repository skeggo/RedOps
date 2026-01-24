#!/usr/bin/env bash
set -euo pipefail

TOOLS_YAML="${1:-/app/tools.yaml}"

if [[ ! -f "$TOOLS_YAML" ]]; then
  echo "[install-tools] tools.yaml not found: $TOOLS_YAML" >&2
  exit 1
fi

python3 - "$TOOLS_YAML" <<'PY'
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

import yaml


def log(msg: str) -> None:
	print(f"[install-tools] {msg}", flush=True)


def detect_arch_token() -> str:
	machine = os.uname().machine
	if machine in ("x86_64", "amd64"):
		return "linux_amd64"
	if machine in ("aarch64", "arm64"):
		return "linux_arm64"
	raise RuntimeError(f"Unsupported architecture: {machine}")


def github_latest_release_asset(repo: str, asset_regex: str) -> tuple[str, str]:
	api = f"https://api.github.com/repos/{repo}/releases/latest"
	req = urllib.request.Request(
		api,
		headers={"Accept": "application/vnd.github+json", "User-Agent": "install-tools"},
	)
	with urllib.request.urlopen(req, timeout=30) as r:
		data = json.loads(r.read().decode("utf-8"))

	assets = data.get("assets") or []
	pattern = re.compile(asset_regex)
	for asset in assets:
		name = asset.get("name") or ""
		if pattern.search(name):
			url = asset.get("browser_download_url")
			if not url:
				continue
			return name, url

	raise RuntimeError(f"No asset matched regex={asset_regex} for repo={repo}")


def download(url: str, dst: Path) -> None:
	dst.parent.mkdir(parents=True, exist_ok=True)
	req = urllib.request.Request(url, headers={"User-Agent": "install-tools"})
	with urllib.request.urlopen(req, timeout=120) as r, open(dst, "wb") as f:
		shutil.copyfileobj(r, f)


def ensure_executable(path: Path) -> None:
	try:
		mode = path.stat().st_mode
		path.chmod(mode | 0o111)
	except Exception:
		pass


def install_github_zip(repo: str, asset_regex: str, bin_name: str, arch_token: str) -> None:
	regex = asset_regex.replace("{arch}", arch_token)
	asset_name, url = github_latest_release_asset(repo, regex)
	log(f"github_zip {repo} asset={asset_name}")

	zip_path = Path("/tmp") / asset_name
	download(url, zip_path)

	subprocess.check_call(["unzip", "-o", str(zip_path), "-d", "/tmp/extract"], stdout=subprocess.DEVNULL)
	zip_path.unlink(missing_ok=True)

	extracted = Path("/tmp/extract")
	candidates = list(extracted.rglob(bin_name))
	if not candidates:
		# Some zips contain a folder; try any file with that name.
		candidates = [p for p in extracted.rglob("*") if p.is_file() and p.name == bin_name]

	if not candidates:
		raise RuntimeError(f"Could not find binary {bin_name} in extracted zip")

	dst = Path("/usr/local/bin") / bin_name
	shutil.copy2(candidates[0], dst)
	ensure_executable(dst)
	shutil.rmtree(extracted, ignore_errors=True)


def install_github_targz(repo: str, asset_regex: str, bin_name: str, arch_token: str) -> None:
	regex = asset_regex.replace("{arch}", arch_token)
	asset_name, url = github_latest_release_asset(repo, regex)
	log(f"github_targz {repo} asset={asset_name}")

	tgz_path = Path("/tmp") / asset_name
	download(url, tgz_path)

	with tempfile.TemporaryDirectory(prefix="extract-") as td:
		subprocess.check_call(["tar", "-xzf", str(tgz_path), "-C", td])
		tgz_path.unlink(missing_ok=True)

		extracted = Path(td)
		candidates = [p for p in extracted.rglob("*") if p.is_file() and p.name == bin_name]
		if not candidates:
			raise RuntimeError(f"Could not find binary {bin_name} in extracted tar.gz")

		dst = Path("/usr/local/bin") / bin_name
		shutil.copy2(candidates[0], dst)
		ensure_executable(dst)


def install_git(repo_url: str, link: str | None, target: str | None, name: str) -> None:
	if link and link.startswith("/opt/"):
		dest = "/" + "/".join(link.strip("/").split("/")[:2])
	else:
		dest = f"/opt/{name}"

	log(f"git {repo_url} -> {dest}")
	shutil.rmtree(dest, ignore_errors=True)
	subprocess.check_call(["git", "clone", "--depth", "1", repo_url, dest], stdout=subprocess.DEVNULL)

	if link and target:
		Path(target).parent.mkdir(parents=True, exist_ok=True)
		try:
			if os.path.islink(target) or os.path.exists(target):
				os.remove(target)
		except FileNotFoundError:
			pass
		os.symlink(link, target)
		ensure_executable(Path(link))


def main() -> int:
	manifest_path = sys.argv[1]
	with open(manifest_path, "r") as f:
		manifest = yaml.safe_load(f) or {}

	tools = manifest.get("tools") or []
	arch_token = detect_arch_token()
	log(f"arch={arch_token}")

	for t in tools:
		name = t.get("name")
		ttype = t.get("type")
		if not name or not ttype:
			continue

		if ttype == "github_zip":
			install_github_zip(
				repo=t["repo"],
				asset_regex=t["asset_regex"],
				bin_name=t["bin_name"],
				arch_token=arch_token,
			)
		elif ttype == "github_targz":
			install_github_targz(
				repo=t["repo"],
				asset_regex=t["asset_regex"],
				bin_name=t["bin_name"],
				arch_token=arch_token,
			)
		elif ttype == "git":
			install_git(
				repo_url=t["repo_url"],
				link=t.get("link"),
				target=t.get("target"),
				name=name,
			)
		else:
			raise RuntimeError(f"Unsupported tool type: {ttype} (tool={name})")

		# quick sanity
		if ttype in ("github_zip", "github_targz"):
			bin_path = shutil.which(t["bin_name"])
			if not bin_path:
				raise RuntimeError(f"Binary not on PATH after install: {t['bin_name']}")

	log("done")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
PY
