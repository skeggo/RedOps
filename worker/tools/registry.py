from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Optional


@dataclass(frozen=True)
class ToolContext:
    scan_id: str
    live_urls: list[str]
    base_url: Optional[str]

    run: Callable[[list[str], int], str]
    insert_finding: Callable[[str, str, dict], None]
    log: Callable[[str], None]

    fast_mode: bool
    env: Mapping[str, str]


ToolFn = Callable[[ToolContext], None]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    fn: ToolFn
    enabled_env: Optional[str] = None
    enabled_default: str = "0"
    order: int = 100

    def is_enabled(self) -> bool:
        if not self.enabled_env:
            return True
        return os.getenv(self.enabled_env, self.enabled_default) == "1"


_REGISTRY: list[ToolSpec] = []


def tool(
    *,
    name: str,
    enabled_env: Optional[str] = None,
    enabled_default: str = "0",
    order: int = 100,
):
    """Decorator to register a tool function.

    Example:
        @tool(name="nikto", enabled_env="ENABLE_NIKTO", order=10)
        def run_nikto(ctx: ToolContext):
            ...
    """

    def decorator(fn: ToolFn) -> ToolFn:
        _REGISTRY.append(
            ToolSpec(
                name=name,
                fn=fn,
                enabled_env=enabled_env,
                enabled_default=enabled_default,
                order=order,
            )
        )
        return fn

    return decorator


def get_registered_tools() -> Iterable[ToolSpec]:
    return sorted(_REGISTRY, key=lambda t: (t.order, t.name))
