from __future__ import annotations

from dissect.target import container, volume
from dissect.target.filesystems.fatx import FatxFilesystem
from tests._utils import absolute_path


def test_fatx() -> None:
    """Test that we can correctly detect and load a FATX filesystem."""
    with absolute_path("_data/volumes/xbox/xbox_hdd.qcow2").open("rb") as fh:
        disk = container.open(fh)
        vs = volume.open(disk)

        c_vol = next(v for v in vs.volumes if v.name == "C")

        assert FatxFilesystem.detect(c_vol)

        fs = FatxFilesystem(c_vol)
        assert fs.serial == 0xD032E
        assert fs.get("/").is_dir()
        assert list(fs.get("/").iterdir()) == ["xboxdash.xbe"]

        file = fs.get("xboxdash.xbe")
        assert not file.is_dir()
        assert file.is_file()
        assert file.stat().st_size == 1916928

        with file.open() as fh:
            assert fh.read(4) == b"XBEH"
