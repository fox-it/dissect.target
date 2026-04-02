from __future__ import annotations

import sys
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import ModuleType

    import pytest


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent.joinpath(filename).resolve()


def mkdirs(root: Path, paths: list[str]) -> None:
    for path in paths:
        root.joinpath(path).mkdir(parents=True)


@contextmanager
def cleanup_modules(modules: list[str], monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Removes or reverts modules back into sys.modules.

    There can be cases that a "tainted" module gets imported using monkeypatch.
    This still has references to the mock objects and effects other tests.
    """
    prev_modules: dict[str, ModuleType | None] = {}
    with monkeypatch.context() as m:
        for mod in modules:
            prev_modules.update({mod: sys.modules.get(mod)})
            # Remove the module inside this monkeypatch context
            if mod in sys.modules:
                m.delitem(sys.modules, mod)

        yield

    for name, module in prev_modules.items():
        if module is None and name in sys.modules:
            # Delete the module if it was created during the test
            del sys.modules[name]
