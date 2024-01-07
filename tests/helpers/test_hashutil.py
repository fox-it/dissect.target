from pathlib import Path
from unittest.mock import Mock, patch

import pytest

import dissect.target.helpers.hashutil as hashutil
from dissect.target import Target
from dissect.target.exceptions import FileNotFoundError

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


def test_hash_uri_records() -> None:
    with pytest.deprecated_call():
        with patch("dissect.target.helpers.record_modifier.get_modifier_function", autospec=True) as modifier_func:
            target = Mock()
            record = Mock()
            hashutil.hash_uri_records(target, record)
            modifier_func.assert_called_with("hash")
            modifier_func.return_value(target, record)


def test_hash_uri(mock_target: Target) -> None:
    """Determine hash functions"""
    path = "/test/path"
    with (
        pytest.deprecated_call(),
        patch.object(mock_target, "resolve", side_effect=resolve_func),
    ):
        output = hashutil.hash_uri(mock_target, path)

    assert output[0] == str(resolve_func(path))
    assert output[1] == HASHES


def test_hash_uri_none() -> None:
    """Determine hash functions"""
    with pytest.deprecated_call(), pytest.raises(FileNotFoundError):
        hashutil.hash_uri(Mock(), None)
