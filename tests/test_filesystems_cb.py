import sys
from unittest.mock import MagicMock

import pytest

from dissect.target.exceptions import NotADirectoryError


def test_cb_filesystem_windows(monkeypatch) -> None:
    with monkeypatch.context() as m:
        mock_cbc_sdk = MagicMock()
        m.setitem(sys.modules, "cbc_sdk", mock_cbc_sdk)
        m.setitem(sys.modules, "cbc_sdk.live_response_api", mock_cbc_sdk.live_response_api)

        from dissect.target.filesystems.cb import OS, CbFilesystem

        mock_session = MagicMock()
        mock_session.os_type = OS.WINDOWS
        mock_session.list_directory.return_value = [
            {
                "filename": "System32",
                "attributes": ["DIRECTORY"],
                "last_access_time": "2077-01-01T00:00:00Z",
                "last_write_time": "2022-10-04T00:00:00Z",
                "create_time": "2069-01-01T00:00:00Z",
                "size": 0,
            }
        ]

        fs = CbFilesystem(mock_session, "C:\\")

        root = fs.get("")
        mock_session.list_directory.assert_not_called()

        assert root.path == ""
        assert root.is_dir()
        assert not root.is_file()
        assert not root.is_symlink()

        entry = fs.get("windows/system32")
        mock_session.list_directory.assert_called_with("c:\\windows\\system32")

        assert entry.path == "windows/system32"
        assert entry.name == "system32"
        assert entry.is_dir()
        assert not entry.is_file()
        assert not entry.is_symlink()

        mock_session.list_directory.return_value = [
            {
                "filename": "myfile.txt",
                "attributes": ["ARCHIVE"],
                "last_access_time": "2077-01-01T00:00:00Z",
                "last_write_time": "2022-10-04T00:00:00Z",
                "create_time": "2069-01-01T00:00:00Z",
                "size": 0,
            }
        ]

        entries = list(entry.scandir())
        mock_session.list_directory.assert_called_with("c:\\windows\\system32\\")

        assert len(entries) == 1
        assert entries[0].path == "windows/system32/myfile.txt"
        assert entries[0].name == "myfile.txt"
        assert not entries[0].is_dir()
        assert entries[0].is_file()
        assert not entries[0].is_symlink()

        with pytest.raises(NotADirectoryError):
            entries[0].listdir()

        entries[0].open()
        mock_session.get_raw_file.assert_called_with("c:\\windows\\system32\\myfile.txt")

        stat_result = entries[0].stat()
        assert stat_result.st_mode == 0o100755
        assert stat_result.st_ino == 3013187826
        assert stat_result.st_atime == 3376684800.0
        assert stat_result.st_mtime == 1664841600.0
        assert stat_result.st_ctime == 3124224000.0
