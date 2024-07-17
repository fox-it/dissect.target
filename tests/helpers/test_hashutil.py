from pathlib import Path

import pytest

import dissect.target.helpers.hashutil as hashutil
from dissect.target import Target

HASHES = ("CAFEF00D" * 4, "F4CEF001" * 5, "DEADBEEF" * 8)


@pytest.fixture
def mock_target(target_win) -> Target:
    target_win.fs.hash = lambda path: HASHES
    target_win.resolve = lambda path: Path(path)
    return target_win


def resolve_func(resolvable_path: str) -> str:
    return Path(f"/resolved{resolvable_path}")


def test_common() -> None:
    fh = open(__file__, "rb")
    output = hashutil.common(fh)

    assert len(output[0]) == 32
    assert len(output[1]) == 40
    assert len(output[2]) == 64
