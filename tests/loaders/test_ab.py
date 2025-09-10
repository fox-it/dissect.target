from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Callable

import pytest

from dissect.target.helpers import keychain
from dissect.target.loader import open as loader_open
from dissect.target.loaders.ab import AndroidBackupLoader
from dissect.target.loaders.ab import main as ab_main
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target]) -> None:
    """Test that we correctly use ``AndroidBackupLoader`` when opening a ``Target``."""
    path = absolute_path("_data/loaders/ab/test.ab")
    keychain.register_wildcard_value("password")

    target = opener(path)
    assert isinstance(target._loader, AndroidBackupLoader)
    assert target.path == path


def test_loader() -> None:
    """Test the Android Backup loader."""
    path = absolute_path("_data/loaders/ab/test.ab")
    keychain.register_wildcard_value("password")

    loader = loader_open(path)
    assert isinstance(loader, AndroidBackupLoader)

    t = Target()
    loader.map(t)
    assert len(t.filesystems) == 1

    assert list(map(str, t.fs.path("/").rglob("*"))) == [
        "/data",
        "/data/data",
        "/data/data/org.fedorahosted.freeotp",
        "/data/data/org.fedorahosted.freeotp/shared_preferences",
        "/data/data/org.fedorahosted.freeotp/shared_preferences/tokenBackup.xml",
    ]

    buf = t.fs.path("/data/data/org.fedorahosted.freeotp/shared_preferences/tokenBackup.xml").read_bytes()
    assert hashlib.sha1(buf).hexdigest() == "7177d340414d5ca2a835603c347e64e3d2625e47"


def test_unwrapper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test the Android Backup unwrapper script."""
    path = absolute_path("_data/loaders/ab/test.ab")

    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["python", str(path), "-p", "password", "-o", str(tmp_path)])
        ab_main()

        assert [entry.name for entry in tmp_path.iterdir()] == ["test.plain.ab"]

        m.setattr("sys.argv", ["python", str(path), "-p", "password", "-o", str(tmp_path), "-t"])
        ab_main()

        assert sorted([entry.name for entry in tmp_path.iterdir()]) == ["test.plain.ab", "test.tar"]
