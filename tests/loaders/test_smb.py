from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Callable
from unittest.mock import MagicMock, patch

import pytest

from dissect.target.target import Target

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def mock_impacket(monkeypatch: pytest.MonkeyPatch) -> Iterator[MagicMock]:
    with monkeypatch.context() as m:
        if "dissect.target.loaders.smb" in sys.modules:
            m.delitem(sys.modules, "dissect.target.loaders.smb")
        if "dissect.target.filesystems.smb" in sys.modules:
            m.delitem(sys.modules, "dissect.target.filesystems.smb")

        mock_impacket = MagicMock()
        m.setitem(sys.modules, "impacket", mock_impacket)
        m.setitem(sys.modules, "impacket.dcerpc", mock_impacket.dcerpc)
        m.setitem(sys.modules, "impacket.dcerpc.v5", mock_impacket.dcerpc.v5)
        m.setitem(sys.modules, "impacket.dcerpc.v5.rpcrt", mock_impacket.dcerpc.v5.rpcrt)
        m.setitem(sys.modules, "impacket.nt_errors", mock_impacket.nt_errors)
        m.setitem(sys.modules, "impacket.smb", mock_impacket.smb)
        m.setitem(sys.modules, "impacket.smb3structs", mock_impacket.smb3structs)
        m.setitem(sys.modules, "impacket.smbconnection", mock_impacket.smbconnection)

        yield mock_impacket


@pytest.fixture
def mock_connection(mock_impacket: MagicMock) -> MagicMock:
    mock_connection = MagicMock()
    mock_impacket.smbconnection.SMBConnection.return_value = mock_connection

    return mock_connection


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target], mock_connection: MagicMock) -> None:
    """Test that we correctly use ``SmbLoader`` when opening a ``Target``."""
    from dissect.target.loaders.smb import SmbLoader

    path = "smb://user@host"
    with patch("dissect.target.target.Target.apply"):
        target = opener(path)
        assert isinstance(target._loader, SmbLoader)
        assert target.path == Path("host")


def test_loader(mock_impacket: MagicMock, mock_connection: MagicMock) -> None:
    from dissect.target.filesystems.smb import SmbFilesystem
    from dissect.target.loader import open as loader_open
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
