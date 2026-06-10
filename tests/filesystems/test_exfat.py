from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

from dissect.target.filesystems.exfat import ExFatFilesystem
from tests._utils import absolute_path


def test_exfat() -> None:
    """Test that we can correctly detect and load an exFAT filesystem."""
    with absolute_path("_data/filesystems/exfat/exfat.bin").open("rb") as fh:
        assert ExFatFilesystem.detect(fh)

        fs = ExFatFilesystem(fh)
        assert fs.serial == 0x6859A296
        assert fs.get("/").is_dir()
        assert list(fs.get("/").iterdir()) == [
            "$ALLOC_BITMAP",
            "$UPCASE_TABLE",
            "System Volume Information",
            "find_me.txt",
            "cat.jpg",
            "directory",
        ]

        file = fs.get("find_me.txt")
        assert not file.is_dir()
        assert file.is_file()
        assert file.stat().st_size == 9

        with file.open() as fh:
            assert fh.read() == b"found me!"

        dir = fs.get("directory")
        assert dir.is_dir()
        assert list(dir.iterdir()) == ["putty.exe"]


def test_exfat_identifier_no_guid() -> None:
    """ExFAT.identifier fallback using exfat.vbr.volume_serial when volume.guid is None."""
    dummy_fh = BytesIO(b"")  # empty in-memory file handle
    with patch("dissect.target.filesystems.exfat.ExFatFilesystem.__init__", lambda self, fh: None):
        fs = ExFatFilesystem(fh=dummy_fh)
        fs.volume = Mock(guid=None)
        fs.exfat = Mock(volume_id="3ade68b1")

        expected_uuid = "987654321"
        assert fs.identifier == expected_uuid
