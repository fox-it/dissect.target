from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.helpers import keychain
from dissect.target.loaders.ab import AndroidBackupLoader
from dissect.target.loaders.ab import main as ab_main
from tests._utils import absolute_path

if TYPE_CHECKING:
    import pytest

    from dissect.target.target import Target


def test_ab_loader(target_bare: Target) -> None:
    ab_path = Path(absolute_path("_data/loaders/ab/test.ab"))
    keychain.register_wildcard_value("password")

    assert AndroidBackupLoader.detect(ab_path)

    loader = AndroidBackupLoader(ab_path)
    loader.map(target_bare)

    assert len(target_bare.filesystems) == 1

    assert list(map(str, target_bare.fs.path("/").rglob("*"))) == [
        "/data",
        "/data/data",
        "/data/data/org.fedorahosted.freeotp",
        "/data/data/org.fedorahosted.freeotp/shared_preferences",
        "/data/data/org.fedorahosted.freeotp/shared_preferences/tokenBackup.xml",
    ]

    buf = target_bare.fs.path("/data/data/org.fedorahosted.freeotp/shared_preferences/tokenBackup.xml").read_bytes()
    assert hashlib.sha1(buf).hexdigest() == "7177d340414d5ca2a835603c347e64e3d2625e47"


def test_ab_unwrapper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ab_path = Path(absolute_path("_data/loaders/ab/test.ab"))

    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["python", str(ab_path), "-p", "password", "-o", str(tmp_path)])
        ab_main()

        assert [entry.name for entry in tmp_path.iterdir()] == ["test.plain.ab"]

        m.setattr("sys.argv", ["python", str(ab_path), "-p", "password", "-o", str(tmp_path), "-t"])
        ab_main()

        assert sorted([entry.name for entry in tmp_path.iterdir()]) == ["test.plain.ab", "test.tar"]
