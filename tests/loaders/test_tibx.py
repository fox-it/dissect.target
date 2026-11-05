from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

import pytest

from dissect.target.exceptions import LoaderError
from dissect.target.helpers import keychain
from dissect.target.loader import open as loader_open
from dissect.target.loaders.tibx import TibxLoader
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

# Archives written by Acronis Cyber Protect 15, the same as in dissect.archive's tests. Each holds
# one NTFS partition, and each backup added a line to its changelog.txt
CHAIN_INC = "_data/loaders/tibx/t1_chain_inc.tibx"  # A full backup and two incrementals
CHAIN_DIFF = "_data/loaders/tibx/t1_chain_diff.tibx"  # A full backup, and a differential in t1_chain_diff-0001.tibx
ENCRYPTED = "_data/loaders/tibx/t1_enc_aes.tibx"  # A full backup, encrypted with AES-256

PASSWORD = "dissect"


def _loader(path: Path, query: str = "") -> TibxLoader:
    return TibxLoader(path, parsed_path=urlparse(f"tibx://{path.name}?{query}"))


def _read_changelog(loader: TibxLoader) -> bytes:
    target = Target()
    loader.map(target)
    target.apply()
    return target.filesystems[0].path("/changelog.txt").read_bytes()


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target]) -> None:
    """Test that we correctly use ``TibxLoader`` when opening a ``Target``."""
    path = absolute_path(CHAIN_INC)

    target = opener(path)
    assert isinstance(target._loader, TibxLoader)
    assert target.path == path


def test_detect(tmp_path: Path) -> None:
    """Test that ``TibxLoader`` detects ``.tibx`` files, except the later parts of a split archive."""
    path = absolute_path(CHAIN_DIFF)
    assert TibxLoader.detect(path)
    # The parts after the first file are read along with it
    assert not TibxLoader.detect(path.with_name("t1_chain_diff-0001.tibx"))

    # Named like a part, but there is no first file next to it
    standalone = tmp_path / "Backup-2024.tibx"
    standalone.write_bytes(absolute_path(CHAIN_INC).read_bytes())
    assert TibxLoader.detect(standalone)

    assert not TibxLoader.detect(tmp_path / "t1_chain_diff.vbk")


def test_loader() -> None:
    """Test that ``TibxLoader`` maps the backed-up partition, and only that, as a volume."""
    path = absolute_path(CHAIN_INC)

    loader = loader_open(path)
    assert isinstance(loader, TibxLoader)
    # Acronis keys its own metadata by volume id just like the partition
    assert len(loader.tibx.streams()) > 1

    target = Target()
    loader.map(target)
    assert [(volume.name, volume.size) for volume in target.volumes] == [("tibx_4", 50331648)]

    target.apply()
    assert [filesystem.__type__ for filesystem in target.filesystems] == ["ntfs"]


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("", b"base\ninc1\ninc2\n"),
        ("recovery-point=0", b"base\n"),
        ("recovery-point=1", b"base\ninc1\n"),
        ("recovery-point=2", b"base\ninc1\ninc2\n"),
        ("recovery-point=oldest", b"base\n"),
        ("recovery-point=latest", b"base\ninc1\ninc2\n"),
    ],
)
def test_recovery_point(query: str, expected: bytes) -> None:
    """Test that the latest backup is loaded by default, and ``recovery-point`` selects another."""
    assert _read_changelog(_loader(absolute_path(CHAIN_INC), query)) == expected


@pytest.mark.parametrize("value", ["3", "-1", "bogus"])
def test_invalid_recovery_point(value: str) -> None:
    with pytest.raises(LoaderError, match="Invalid recovery point"):
        _loader(absolute_path(CHAIN_INC), f"recovery-point={value}")


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("", b"base\ndiff\n"),
        ("recovery-point=0", b"base\n"),
    ],
)
def test_split_archive(query: str, expected: bytes) -> None:
    """Test that a backup stored in a later part of the archive is loaded."""
    assert _read_changelog(_loader(absolute_path(CHAIN_DIFF), query)) == expected


def test_split_archive_in_directory(tmp_path: Path) -> None:
    """Test that a directory holding a split archive loads its backup once, not once per part."""
    for name in ("t1_chain_diff.tibx", "t1_chain_diff-0001.tibx"):
        (tmp_path / name).write_bytes(absolute_path(CHAIN_DIFF).with_name(name).read_bytes())

    targets = [target for target in Target.open_all([tmp_path]) if isinstance(target._loader, TibxLoader)]
    assert [target.path.name for target in targets] == ["t1_chain_diff.tibx"]


@pytest.mark.parametrize("keys", [[], [("wrong", "tibx")]])
def test_encrypted_without_password(keys: list[tuple[str, str]]) -> None:
    for value, provider in keys:
        keychain.register_key(keychain.KeyType.PASSPHRASE, value, provider=provider)

    with pytest.raises(LoaderError, match="Missing password"):
        TibxLoader(absolute_path(ENCRYPTED))


def test_encrypted_with_keychain_password() -> None:
    """Test that the passphrases in the keychain are tried until one unlocks the archive."""
    keychain.register_key(keychain.KeyType.PASSPHRASE, "wrong", provider="tibx")
    keychain.register_key(keychain.KeyType.PASSPHRASE, PASSWORD)

    assert _read_changelog(TibxLoader(absolute_path(ENCRYPTED))) == b"base\n"


def test_open_error(tmp_path: Path) -> None:
    """Test that a damaged archive is still detected, and fails with a clear error."""
    path = tmp_path / "truncated.tibx"
    path.write_bytes(absolute_path(CHAIN_INC).read_bytes()[:16])

    assert TibxLoader.detect(path)
    with pytest.raises(LoaderError, match="Failed to open TIBX archive"):
        TibxLoader(path)
