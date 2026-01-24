from __future__ import annotations

import importlib
import pkgutil
from types import ModuleType
from typing import Iterable


def discover_and_import(package_name: str) -> list[ModuleType]:
    """Import all modules in a package (non-recursive).

    This is used for tool auto-discovery: each module registers tools via decorators.
    """

    pkg = importlib.import_module(package_name)
    if not hasattr(pkg, "__path__"):
        return []

    imported: list[ModuleType] = []
    for m in pkgutil.iter_modules(pkg.__path__, prefix=f"{package_name}."):
        # Ignore private/dunder modules.
        short_name = m.name.rsplit(".", 1)[-1]
        if short_name.startswith("_"):
            continue
        imported.append(importlib.import_module(m.name))

    return imported
