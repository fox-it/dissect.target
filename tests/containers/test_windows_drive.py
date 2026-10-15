from __future__ import annotations

import io
from io import BytesIO
from unittest import mock

from dissect.target import container
from dissect.target.containers.windows_drive import WindowsDrive
from dissect.target.filesystem import VirtualFilesystem


def test_windows_drive_detect_path() -> None:
    """Test that Windows drive containers are properly opened, when using the path based matching.

    Windows API call are mocked, and thus not tested.
    """
    vfs = VirtualFilesystem()
    with (
        mock.patch("dissect.target.containers.windows_drive.run_on_windows", return_value=True),
        mock.patch(
            "dissect.target.containers.windows_drive._windows_get_disk_size", return_value=18
        ) as mock_windows_get_disk_size,
        mock.patch(
            "dissect.target.containers.windows_drive._windows_get_drive_size", return_value=18
        ) as mock_windows_get_drive_size,
    ):
        vfs.map_file_fh("\\\\.\\PhysicalDrive5", BytesIO(b'echo "hello world"'))
        vfs.map_file_fh("\\\\.\\C:", BytesIO(b'echo "hello world"'))

        fh = container.open(vfs.path("\\\\.\\PhysicalDrive5"))
        assert isinstance(fh, WindowsDrive)
        assert mock_windows_get_disk_size.call_count == 1
        assert mock_windows_get_drive_size.call_count == 0
        a = fh.read(20)
        assert a == b'echo "hello world"'
        assert fh.tell() == 18
        fh.seek(0, whence=io.SEEK_END)
        assert fh.tell() == 18
        fh.close()

        fh = container.open(vfs.path("\\\\.\\C:"))
        assert isinstance(fh, WindowsDrive)
        assert mock_windows_get_disk_size.call_count == 1
        assert mock_windows_get_drive_size.call_count == 1
        a = fh.read(20)
        assert a == b'echo "hello world"'
        assert fh.tell() == 18
        fh.seek(0, whence=io.SEEK_END)
        assert fh.tell() == 18
        fh.close()
