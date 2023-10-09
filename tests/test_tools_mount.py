from io import BytesIO
from unittest.mock import patch

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.target import Target
from dissect.target.tools.mount import main as target_mount
from dissect.target.volume import Volume


def test_duplicate_volume_name(target_bare: Target, monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["target-mount", "mock-target", "mock-mount"])
        m.setattr("dissect.target.tools.mount.HAS_FUSE", True)

        with patch("dissect.target.tools.mount.Target") as MockTarget, patch(
            "dissect.target.tools.mount.FUSE", create=True
        ) as MockFUSE, patch("dissect.target.tools.mount.DissectMount", create=True) as MockDissectMount:
            MockTarget.open.return_value = target_bare

            target_bare.volumes.add(Volume(BytesIO(), 1, 0, 0, None, name="first"))
            target_bare.volumes.add(Volume(BytesIO(), 2, 0, 0, None, name="second"))
            target_bare.volumes.add(Volume(BytesIO(), 3, 0, 0, None, name="second_1"))
            target_bare.volumes.add(Volume(BytesIO(), 4, 0, 0, None, name="second"))

            mock_fs = VirtualFilesystem()
            mock_fs.volume = target_bare.volumes[1]
            target_bare.filesystems.add(mock_fs)
            mock_fs = VirtualFilesystem()
            mock_fs.volume = target_bare.volumes[2]
            target_bare.filesystems.add(mock_fs)
            mock_fs = VirtualFilesystem()
            mock_fs.volume = target_bare.volumes[3]
            target_bare.filesystems.add(mock_fs)

            target_mount()

            MockFUSE.assert_called_once()
            MockDissectMount.assert_called_once()
            vfs = MockDissectMount.call_args[0][0]

            assert vfs.listdir("/volumes") == ["first", "second", "second_1", "second_2"]
            assert vfs.listdir("/filesystems") == ["second", "second_1", "second_2"]
