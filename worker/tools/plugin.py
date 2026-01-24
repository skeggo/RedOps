from __future__ import annotations

import importlib
from typing import Any, Protocol


class ToolModule(Protocol):
    NAME: str

    def can_run(self, ctx: dict[str, Any]) -> bool:  # type: ignore[override]
        ...

    def run(self, ctx: dict[str, Any], *, timeout: int, args: dict[str, Any] | None = None) -> dict[str, Any]:  # type: ignore[override]
        ...


def load_tool(name: str) -> ToolModule:
    mod = importlib.import_module(f"tools.{name}")

    tool_name = getattr(mod, "NAME", None)
    can_run = getattr(mod, "can_run", None)
    run = getattr(mod, "run", None)

    if not tool_name or not callable(can_run) or not callable(run):
        raise RuntimeError(
            f"Tool module tools.{name} must define NAME, can_run(ctx), run(ctx, timeout=..., args=...)"
        )

    return mod  # type: ignore[return-value]
