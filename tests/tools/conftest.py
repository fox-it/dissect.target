from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.tools.logging import configure_logging

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def prevent_logging_setup(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def noop(*args, **kwargs) -> None:
        pass

    with monkeypatch.context() as m:
        m.setattr(configure_logging, "__code__", noop.__code__)
        yield
