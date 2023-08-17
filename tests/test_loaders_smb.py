import sys
from typing import Iterator
from unittest.mock import MagicMock

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.target import Target


@pytest.fixture
def mock_impacket(monkeypatch: pytest.MonkeyPatch) -> Iterator[MagicMock]:
    with monkeypatch.context() as m:
        mock_impacket = MagicMock()
        m.setitem(sys.modules, "impacket", mock_impacket)
        m.setitem(sys.modules, "impacket.dcerpc", mock_impacket.dcerpc)
        m.setitem(sys.modules, "impacket.dcerpc.v5", mock_impacket.dcerpc.v5)
        m.setitem(sys.modules, "impacket.smb", mock_impacket.smb)
        m.setitem(sys.modules, "impacket.smb3structs", mock_impacket.smb3structs)
        m.setitem(sys.modules, "impacket.smbconnection", mock_impacket.smbconnection)

        yield mock_impacket


@pytest.fixture
def mock_connection(mock_impacket: MagicMock) -> MagicMock:
    mock_connection = MagicMock()
    mock_impacket.smbconnection.SMBConnection.return_value = mock_connection

    yield mock_connection


def test_smb_loader(mock_impacket: MagicMock, mock_connection: MagicMock) -> None:
    from dissect.target.filesystems.smb import SmbFilesystem
    from dissect.target.loaders.smb import SmbLoader, SmbRegistry

    loader = loader_open("smb://user@host")
    assert isinstance(loader, SmbLoader)
    assert loader._conn is mock_connection
    mock_impacket.smbconnection.SMBConnection.assert_called_with(
        remoteName="host", remoteHost="host", myName=SmbLoader.MACHINE_NAME
    )
    mock_connection.login.assert_called_with(
        domain=".", user="user", password="", nthash=SmbLoader.EMPTY_NT, lmhash=SmbLoader.EMPTY_LM
    )

    mock_connection.listShares.return_value = [{"shi1_netname": "C$\x00"}]

    t = Target()
    loader.map(t)

    assert len(t.filesystems) == 1
    assert isinstance(t.fs.mounts["c:"], SmbFilesystem)
    assert t.fs.mounts["c:"].share_name == "C$"

    assert len(t._plugins) == 1
    assert isinstance(t._plugins[0], SmbRegistry)
