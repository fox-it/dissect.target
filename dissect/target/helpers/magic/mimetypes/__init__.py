from __future__ import annotations

import importlib
from pathlib import Path

TYPES = []
MAP = set()
PATTERNS: set[tuple[int, tuple[str]]] = set()

files = [
    Path(__file__).parent.joinpath("freedesktop.py").resolve(),
    *[p for p in Path(__file__).parent.glob("*.py") if p.stem not in ("__init__", "freedesktop", "overrides")],
    Path(__file__).parent.joinpath("overrides.py").resolve(),
]

for file in files:
    obj = importlib.import_module(f"dissect.target.helpers.magic.mimetypes.{file.stem}")

    if not hasattr(obj, "TYPES"):
        raise ValueError(f"Module {obj!s} does not have a TYPES attribute.")

    if not isinstance(obj.TYPES, list):
        raise TypeError(f"Attribute {obj!s}.TYPES is not a list.")

    TYPES += obj.TYPES

for i, definition in enumerate(TYPES):
    if "type" not in definition:
        raise ValueError(f"Magic definition missing type: {definition}")

    if "name" not in definition:
        raise ValueError(f"Magic definition missing name: {definition}")

    if "magic" not in definition and "pattern" not in definition:
        raise ValueError(f"Magic definition missing magic or pattern: {definition}")

    if "pattern" in definition:
        # We only support patterns like `*.foo`, not `foo.*` or `foo*bar`
        PATTERNS.add((i, tuple([p.replace("*", "") for p in definition.get("pattern", [])])))

    for magic in definition.get("magic", []):
        if "value" not in magic:
            raise ValueError(f"Magic definition missing value in {definition}")

        MAP.add((i, magic.get("offset", 0), magic["value"]))
