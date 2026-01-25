import os
import hmac
from functools import lru_cache
from typing import Dict, Tuple

from fastapi import HTTPException, Request


class AuthConfigError(RuntimeError):
    pass


def _split_items(raw: str) -> list[str]:
    raw = (raw or "").strip()
    if not raw:
        return []
    normalized = raw.replace("\n", ",").replace(" ", ",").replace("\t", ",")
    return [p.strip() for p in normalized.split(",") if p.strip()]


@lru_cache(maxsize=1)
def load_api_keys(env_var: str = "API_KEYS") -> Dict[str, str]:
    """Load API keys from env.

    Format: comma/space/newline separated pairs in either form:
      - <id>=<secret>
      - <id>:<secret>

    Example:
      API_KEYS=local=devkey,ci=ci-secret
    """

    raw = os.getenv(env_var, "")
    items = _split_items(raw)
    if not items:
        raise AuthConfigError(f"{env_var} is required and must be non-empty")

    keys: Dict[str, str] = {}
    for item in items:
        if "=" in item:
            key_id, secret = item.split("=", 1)
        elif ":" in item:
            key_id, secret = item.split(":", 1)
        else:
            raise AuthConfigError(
                f"Invalid {env_var} entry '{item}'. Use '<id>=<secret>' (recommended)"
            )

        key_id = key_id.strip()
        secret = secret.strip()
        if not key_id or not secret:
            raise AuthConfigError(f"Invalid {env_var} entry '{item}'")
        if key_id in keys:
            raise AuthConfigError(f"Duplicate API key id in {env_var}: '{key_id}'")
        keys[key_id] = secret

    return keys


def _extract_presented_key(request: Request) -> str | None:
    # Prefer Authorization: Bearer <token>
    authz = request.headers.get("Authorization")
    if authz:
        parts = authz.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1].strip()
            if token:
                return token

    # Fallback: X-API-Key: <token>
    x_api_key = request.headers.get("X-API-Key")
    if x_api_key and x_api_key.strip():
        return x_api_key.strip()

    return None


def authenticate_request(request: Request) -> Tuple[str, str]:
    """Authenticate request using configured API keys.

    Returns (api_key_id, secret) for the matched key.
    """

    presented = _extract_presented_key(request)
    if not presented:
        raise HTTPException(status_code=401, detail="Missing API key")

    try:
        keys = load_api_keys()
    except AuthConfigError as e:
        # Misconfiguration should fail closed.
        raise HTTPException(status_code=503, detail=f"Auth not configured: {e}")

    for key_id, secret in keys.items():
        if hmac.compare_digest(presented, secret):
            return key_id, secret

    raise HTTPException(status_code=403, detail="Invalid API key")
