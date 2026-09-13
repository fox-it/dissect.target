from __future__ import annotations

import sys
from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock

if TYPE_CHECKING:
    import pytest


def test_ssh_filesystem(monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as m:
        if "dissect.target.filesystems.ssh" in sys.modules:
            m.delitem(sys.modules, "dissect.target.filesystems.ssh")

        mock_paramiko = MagicMock()
        m.setitem(sys.modules, "paramiko", mock_paramiko)

        from dissect.target.filesystems.ssh import SftpDialect, SshFilesystem

        fs = SshFilesystem("hostname")
        assert isinstance(fs.dialect, SftpDialect)

        mock_lstat = Mock()
        mock_lstat.filename = "mock"
        mock_lstat.st_mode = 0o40755
        mock_lstat.st_uid = 1000
        mock_lstat.st_gid = 1000
        mock_lstat.st_size = 1234
        mock_lstat.st_atime = 1
        mock_lstat.st_mtime = 2
        fs.dialect.sftp.lstat.return_value = mock_lstat

        entry = fs.get("mock")
        assert entry.lstat().st_mode == 0o40755
        assert entry.lstat().st_uid == 1000
        assert entry.lstat().st_gid == 1000
        assert entry.lstat().st_size == 1234
        assert entry.lstat().st_atime == 1
        assert entry.lstat().st_mtime == 2
        assert entry.lstat().st_ctime == 0

        fs.dialect.sftp.listdir.return_value = ["file1", "file2"]
        assert list(entry.iterdir()) == ["file1", "file2"]

        fs.dialect.sftp.listdir_iter.return_value = [mock_lstat]
        entries = list(entry.scandir())
        assert len(entries) == 1
        assert entries[0].path == "mock/mock"

        entry.entry.st_mode = 0o120777
        fs.dialect.sftp.readlink.return_value = "/some/target"
        assert entry.readlink() == "/some/target"

        entry.entry.st_mode = 0o100644
        fs.dialect.sftp.open.return_value = BytesIO(b"test data")
        with entry.open() as fh:
            assert fh.read() == b"test data"
