from io import BytesIO
from unittest.mock import patch

from dissect.target import volume
from dissect.target.volumes import disk


def test_reset_file_position() -> None:
    fh = BytesIO(b"\x00" * 8192)
    fh.seek(512)

    class MockVolumeSystem(volume.VolumeSystem):
        def __init__(self, fh):
            assert fh.tell() == 0
            fh.seek(1024)
            self.success = True

        @staticmethod
        def _detect(fh):
            assert fh.tell() == 0
            fh.seek(256)
            return True

    with patch.object(disk, "DissectVolumeSystem", MockVolumeSystem):
        assert MockVolumeSystem.detect(fh)
        assert fh.tell() == 512

        opened_vs = volume.open(fh)
        assert isinstance(opened_vs, MockVolumeSystem)
        assert opened_vs.success
        assert fh.tell() == 512
