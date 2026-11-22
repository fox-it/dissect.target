from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugins.apps.backup.tibx import TibxPlugin
from dissect.target.target import Target
from tests.loaders.test_tibx import ARCHIVE_UUID, CHAIN, UNFINISHED, use_synthetic_tibx

if TYPE_CHECKING:
    from pathlib import Path


def _open(path: Path, query: str = "") -> Target:
    target = Target.open(f"tibx://{path}?{query}")
    target.add_plugin(TibxPlugin)
    return target


def test_recovery_points(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Test that every backup in the archive is listed, oldest first, with the one the target shows selected."""
    path = use_synthetic_tibx(monkeypatch, tmp_path, CHAIN)

    records = list(_open(path, "recovery-point=1").tibx.recovery_points())

    assert [record.index for record in records] == [0, 1, 2]
    assert [record.guid for record in records] == [str(point.guid) for point in CHAIN]
    assert [record.type for record in records] == ["FULL", "INCREMENTAL", "INCREMENTAL"]
    assert [record.selected for record in records] == [False, True, False]

    record = records[1]
    assert record.ts_created == CHAIN[1].created
    assert record.ts_finished == CHAIN[1].finished
    assert record.size == 3 * 0x100000
    assert record.compressed_size == 3 * 0x40000
    assert (record.items_added, record.items_changed, record.items_removed) == (3, 6, 9)
    assert not record.unfinished
    assert record.archive_uuid == str(ARCHIVE_UUID)
    assert record.source == path


def test_recovery_points_latest_selected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Test that the newest backup is selected when the latest is loaded by default."""
    path = use_synthetic_tibx(monkeypatch, tmp_path, CHAIN)

    assert [record.selected for record in _open(path).tibx.recovery_points()] == [False, False, True]


def test_recovery_points_unfinished(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Test that a backup that has not finished is listed as such, and not selected by default."""
    path = use_synthetic_tibx(monkeypatch, tmp_path, UNFINISHED)

    records = list(_open(path).tibx.recovery_points())

    assert [record.unfinished for record in records] == [False, False, True]
    assert [record.selected for record in records] == [False, True, False]
    assert records[2].ts_finished is None


@pytest.mark.parametrize(
    ("query", "index", "latest"),
    [
        ("", 2, True),
        ("recovery-point=oldest", 0, False),
        (f"recovery-point={CHAIN[1].guid}", 1, False),
    ],
)
def test_backup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, query: str, index: int, latest: bool) -> None:
    """Test that ``tibx.backup`` names the backup the target shows, and the archive it is in."""
    path = use_synthetic_tibx(monkeypatch, tmp_path, CHAIN)

    (record,) = _open(path, query).tibx.backup()

    assert record.index == index
    assert record.guid == str(CHAIN[index].guid)
    assert record.type == CHAIN[index].type
    assert record.ts_created == CHAIN[index].created
    assert record.ts_finished == CHAIN[index].finished
    assert record.latest == latest
    assert not record.unfinished
    assert record.recovery_points == 3
    assert not record.encrypted
    assert record.archive_uuid == str(ARCHIVE_UUID)
    assert record.source == path
    assert record.parts == [path]
    # Every record of the target names the backup it came from
    assert record._source == f"{path}?recovery-point={CHAIN[index].guid}"


@pytest.mark.parametrize(
    ("query", "index", "latest", "unfinished"),
    [
        ("", 1, True, False),
        ("recovery-point=2", 2, False, True),
    ],
)
def test_backup_unfinished(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, query: str, index: int, latest: bool, unfinished: bool
) -> None:
    """Test that ``tibx.backup`` tells a backup that has not finished, which the latest is not."""
    path = use_synthetic_tibx(monkeypatch, tmp_path, UNFINISHED)

    (record,) = _open(path, query).tibx.backup()

    assert record.index == index
    assert record.latest == latest
    assert record.unfinished == unfinished


def test_backup_without_backups(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Test that an archive recording no backups yields a backup record without backup fields."""
    path = use_synthetic_tibx(monkeypatch, tmp_path, [])

    (record,) = _open(path).tibx.backup()

    assert record.guid is None
    assert record.index is None
    assert record.latest
    assert record.recovery_points == 0
    assert record._source == str(path)


def test_backup_per_target_of_open_all(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Test that the targets ``recovery-point=all`` opens each name their own backup."""
    path = use_synthetic_tibx(monkeypatch, tmp_path, CHAIN)

    backups = []
    for target in Target.open_all([f"tibx://{path}?recovery-point=all"]):
        target.add_plugin(TibxPlugin)
        backups.extend(target.tibx.backup())

    assert [record.guid for record in backups] == [str(point.guid) for point in CHAIN]
    assert [record.latest for record in backups] == [False, False, True]


def test_unsupported() -> None:
    """Test that the plugin refuses targets not loaded from a TIBX archive."""
    with pytest.raises(UnsupportedPluginError, match="not loaded from a TIBX archive"):
        Target().add_plugin(TibxPlugin)
