from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

from dissect.target.exceptions import NotADirectoryError


def test_smb_filesystem_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as m:
        mock_impacket = MagicMock()
        m.setitem(sys.modules, "impacket", mock_impacket)
        m.setitem(sys.modules, "impacket.nt_errors", mock_impacket.nt_errors)
        m.setitem(sys.modules, "impacket.smb", mock_impacket.smb)
        m.setitem(sys.modules, "impacket.smb3structs", mock_impacket.smb3structs)
        m.setitem(sys.modules, "impacket.smbconnection", mock_impacket.smbconnection)

        from dissect.target.filesystems.smb import SmbFilesystem

        mock_dir = MagicMock()
        mock_dir.get_longname.return_value = "testdir"
        mock_dir.is_directory.return_value = True

        mock_conn = MagicMock()
        mock_conn.listPath.return_value = [mock_dir]

        fs = SmbFilesystem(mock_conn, "C$")

        root = fs.get("")
        mock_conn.listPath.assert_not_called()

        assert root.path == ""
        assert root.is_dir()
        assert not root.is_file()
        assert not root.is_symlink()

        entry = fs.get("testdir")
        mock_conn.listPath.assert_called_with("C$", "testdir")

        assert entry.path == "testdir"
        assert entry.name == "testdir"
        assert entry.is_dir()
        assert not entry.is_file()
        assert not entry.is_symlink()

        mock_file = MagicMock()
        mock_file.get_longname.return_value = "testfile.txt"
        mock_file.is_directory.return_value = False
        mock_file.get_filesize.return_value = 69
        mock_file.get_atime_epoch.return_value = 1
        mock_file.get_mtime_epoch.return_value = 2
        mock_file.get_ctime_epoch.return_value = 3

        mock_conn.listPath.return_value = [mock_file]

        entries = list(entry.scandir())
        mock_conn.listPath.assert_called_with("C$", "testdir/*")

        assert len(entries) == 1
        assert entries[0].path == "testdir/testfile.txt"
        assert entries[0].name == "testfile.txt"
        assert not entries[0].is_dir()
        assert entries[0].is_file()
        assert not entries[0].is_symlink()

        with pytest.raises(NotADirectoryError):
            entries[0].listdir()

        entries[0].open()
        mock_conn.connectTree.assert_called_with("C$")
        mock_conn.openFile.assert_called_once()

        stat_result = entries[0].stat()
        assert stat_result.st_mode == 0o100755
        assert stat_result.st_ino == 3086484436
        assert stat_result.st_atime == 1.0
        assert stat_result.st_mtime == 2.0
        assert stat_result.st_ctime == 3.0
