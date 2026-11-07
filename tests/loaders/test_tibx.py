from __future__ import annotations

import io
import uuid
from types import SimpleNamespace
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import pytest
from dissect.archive.tibx import InvalidArchiveError, RecoveryPoint
from dissect.archive.tibx.c_tibx import c_tibx

from dissect.target.exceptions import LoaderError, TargetError
from dissect.target.helpers import keychain
from dissect.target.loader import open as loader_open
from dissect.target.loaders import tibx as tibx_loader
from dissect.target.loaders.tibx import TibxLoader
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from typing_extensions import Self

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
    assert target._loader.path == path
    # The path names the latest backup, as acrocmd lists it
    assert str(target.path).startswith(f"{path}?recovery-point=4b7e07ce-")


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
    assert [target._loader.path.name for target in targets] == ["t1_chain_diff.tibx"]


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


# Synthetic archives, for the tests that need an archive's backups but none of its data.
# SyntheticTibx stands in for dissect.archive's TIBX with the RecoveryPoint objects it would
# return, so these tests need no archive files.

ARCHIVE_UUID = uuid.UUID("0f8fad5b-d9cb-469f-a165-70867728950e")


def synthetic_point(index: int, slice_id: int, slice_type: c_tibx.SliceType, *, finished: bool = True) -> RecoveryPoint:
    """A backup as the slices tree records it, with fields derived from its slice id."""
    record = c_tibx.slice_record(
        guid=uuid.UUID(int=slice_id).bytes_le,
        ctime_ms=1_700_000_000_000 + slice_id * 86_400_000,
        ftime_ms=1_700_000_000_000 + slice_id * 86_400_000 + 600_000 if finished else 0,
        user_size=slice_id * 0x100000,
        compr_size=slice_id * 0x40000,
        items_added=slice_id,
        items_changed=slice_id * 2,
        items_removed=slice_id * 3,
        flags=slice_type,
    )
    return RecoveryPoint(index, slice_id, record)


# A full backup and two incrementals; slice ids need not be contiguous
CHAIN = [
    synthetic_point(0, 2, c_tibx.SliceType.FULL),
    synthetic_point(1, 3, c_tibx.SliceType.INCREMENTAL),
    synthetic_point(2, 5, c_tibx.SliceType.INCREMENTAL),
]

# The same, while its last incremental has not finished
UNFINISHED = [*CHAIN[:2], synthetic_point(2, 5, c_tibx.SliceType.INCREMENTAL, finished=False)]


class SyntheticTibx:
    """An archive holding the backups ``points``, and one volume of zeros that holds no filesystem."""

    def __init__(self, points: list[RecoveryPoint]):
        self.points = points
        self.encrypted = False
        self.uuid = ARCHIVE_UUID
        self.use_recovery_point("latest")

    def recovery_points(self) -> list[RecoveryPoint]:
        return self.points

    def use_recovery_point(self, selector: str) -> None:
        if selector == "latest":
            # The newest backup that has finished
            self.recovery_point = next((point for point in reversed(self.points) if point.finished is not None), None)
            return
        for point in self.points:
            if selector in (str(point.index), str(point.guid)) or (selector == "oldest" and point.index == 0):
                self.recovery_point = point
                return
        raise InvalidArchiveError(f"invalid recovery point {selector!r}")

    def volumes(self) -> list[SimpleNamespace]:
        return [SimpleNamespace(volume_id=4, size=0x10000, open=lambda: io.BytesIO(bytes(0x10000)))]

    def close(self) -> None:
        pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        self.close()


def use_synthetic_tibx(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, points: list[RecoveryPoint]) -> Path:
    """Make the loader open every archive as a synthetic one holding ``points``, and return a path to load."""
    monkeypatch.setattr(tibx_loader, "TIBX", SimpleNamespace(open=lambda path: SyntheticTibx(points)))
    path = tmp_path / "plc-eng01.tibx"
    path.touch()
    return path


def _uri(path: Path, query: str) -> str:
    return f"tibx://{path}?{query}"


def test_find_all(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Test that ``recovery-point=all`` yields a URI per backup, oldest first, naming it by GUID."""
    path = use_synthetic_tibx(monkeypatch, tmp_path, CHAIN)
    parsed = urlparse(_uri(path, "recovery-point=all&peers=2"))

    assert list(TibxLoader.find_all(path, parsed)) == [
        _uri(path, "recovery-point=00000000-0000-0000-0000-000000000002&peers=2"),
        _uri(path, "recovery-point=00000000-0000-0000-0000-000000000003&peers=2"),
        _uri(path, "recovery-point=00000000-0000-0000-0000-000000000005&peers=2"),
    ]


@pytest.mark.parametrize("query", ["", "recovery-point=1", "recovery-point=latest"])
def test_find_all_single(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, query: str) -> None:
    """Test that any other ``recovery-point`` leaves the path to load as it is."""
    path = use_synthetic_tibx(monkeypatch, tmp_path, CHAIN)

    assert [sub_path is path for sub_path in TibxLoader.find_all(path, urlparse(_uri(path, query)))] == [True]
    assert [sub_path is path for sub_path in TibxLoader.find_all(path, None)] == [True]


def test_find_all_without_backups(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Test that an archive recording no backups still yields its live state."""
    path = use_synthetic_tibx(monkeypatch, tmp_path, [])

    assert list(TibxLoader.find_all(path, urlparse(_uri(path, "recovery-point=all")))) == [
        _uri(path, "recovery-point=latest")
    ]


def test_find_all_unreadable(tmp_path: Path) -> None:
    """Test that an archive that cannot be opened is yielded as it is, so loading it reports why."""
    path = tmp_path / "broken.tibx"
    path.write_bytes(b"not a TIBX archive")

    assert [sub_path is path for sub_path in TibxLoader.find_all(path, urlparse(_uri(path, "recovery-point=all")))] == [
        True
    ]


def test_open_all_recovery_points(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Test that ``recovery-point=all`` opens a target per backup, each with a path naming its backup."""
    path = use_synthetic_tibx(monkeypatch, tmp_path, CHAIN)

    targets = list(Target.open_all([_uri(path, "recovery-point=all")]))

    assert [target._loader.tibx.recovery_point for target in targets] == CHAIN
    assert [str(target.path) for target in targets] == [f"{path}?recovery-point={point.guid}" for point in CHAIN]


@pytest.mark.parametrize(
    ("query", "point"),
    [
        ("", CHAIN[-1]),
        ("recovery-point=latest", CHAIN[-1]),
        ("recovery-point=0", CHAIN[0]),
        (f"recovery-point={CHAIN[1].guid}", CHAIN[1]),
    ],
)
def test_target_path_names_backup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, query: str, point: RecoveryPoint
) -> None:
    """Test that the target path names the backup it shows by GUID, and opens that backup again."""
    path = use_synthetic_tibx(monkeypatch, tmp_path, CHAIN)

    target = Target.open(_uri(path, query))
    assert str(target.path) == f"{path}?recovery-point={point.guid}"
    assert Target.open(f"tibx://{target.path}")._loader.tibx.recovery_point is point


def test_target_path_without_backups(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Test that the target path of an archive recording no backups is the archive itself."""
    path = use_synthetic_tibx(monkeypatch, tmp_path, [])

    assert Target.open(path).path == path


def test_open_recovery_point_by_guid(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Test that a GUID from a URI ``find_all`` yields selects that backup."""
    path = use_synthetic_tibx(monkeypatch, tmp_path, CHAIN)

    target = Target.open(_uri(path, f"recovery-point={CHAIN[1].guid}"))
    assert target._loader.tibx.recovery_point is CHAIN[1]


def test_recovery_point_all_needs_open_all(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Test that opening a single target with ``recovery-point=all`` explains why it cannot."""
    path = use_synthetic_tibx(monkeypatch, tmp_path, CHAIN)

    with pytest.raises(LoaderError, match="one target per backup"):
        _loader(path, "recovery-point=all")

    with pytest.raises(TargetError, match="one target per backup"):
        Target.open(_uri(path, "recovery-point=all"))


def test_latest_is_the_newest_finished_backup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Test that a backup that has not finished loads only when selected, and ``all`` opens it too."""
    path = use_synthetic_tibx(monkeypatch, tmp_path, UNFINISHED)

    assert str(Target.open(path).path) == f"{path}?recovery-point={UNFINISHED[1].guid}"
    assert Target.open(_uri(path, "recovery-point=2"))._loader.tibx.recovery_point is UNFINISHED[2]

    targets = list(Target.open_all([_uri(path, "recovery-point=all")]))
    assert [target._loader.tibx.recovery_point for target in targets] == UNFINISHED
