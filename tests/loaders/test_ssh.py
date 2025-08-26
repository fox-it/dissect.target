from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable
from unittest.mock import MagicMock, patch

import pytest

from dissect.target.target import Target


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target], monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that we correctly use ``SshLoader`` when opening a ``Target``."""
    with monkeypatch.context() as m:
        mock_paramiko = MagicMock()
        m.setitem(sys.modules, "paramiko", mock_paramiko)

        from dissect.target.loaders.ssh import SshLoader

        path = "ssh://user@host"
        with patch("dissect.target.target.Target.apply"):
            target = opener(path)
            assert isinstance(target._loader, SshLoader)
            assert target.path == Path("host")


def test_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test the SSH loader."""
    with monkeypatch.context() as m:
        mock_paramiko = MagicMock()
        m.setitem(sys.modules, "paramiko", mock_paramiko)

        from dissect.target.filesystems.ssh import SshFilesystem
        from dissect.target.loader import open as loader_open
        from dissect.target.loaders.ssh import SshLoader

        loader = loader_open("ssh://user@host")
        assert isinstance(loader, SshLoader)

        t = Target()
        loader.map(t)

        assert len(t.filesystems) == 1
        assert isinstance(t.filesystems[0], SshFilesystem)
