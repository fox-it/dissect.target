from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from dissect.target.target import Target

if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target]) -> None:
    """Test that we correctly use ``NetcatListenerLoader`` when opening a ``Target``."""
    with patch("socket.socket") as mock_socket:
        mock_client = Mock()

        mock_socket.return_value = mock_socket
        mock_socket.accept.return_value = (mock_client, ("10.69.69.10", 420))

        from dissect.target.loaders.nc import NetcatListenerLoader

        path = "nc://0.0.0.0:420?dialect=linux"
        with patch("dissect.target.target.Target.apply"):
            target = opener(path)
            assert isinstance(target._loader, NetcatListenerLoader)
            assert target.path == Path("0.0.0.0:420")


def test_loader() -> None:
    """Test the netcat listener loader."""
    with patch("socket.socket") as mock_socket:
        mock_client = Mock()

        mock_socket.return_value = mock_socket
        mock_socket.accept.return_value = (mock_client, ("10.69.69.10", 420))

        from dissect.target.filesystems.nc import NetcatListenerFilesystem
        from dissect.target.loader import open as loader_open
        from dissect.target.loaders.nc import NetcatListenerLoader

        loader = loader_open("nc://0.0.0.0:420?dialect=linux")
        assert isinstance(loader, NetcatListenerLoader)

        t = Target()
        loader.map(t)

        assert len(t.filesystems) == 1
        assert isinstance(t.filesystems[0], NetcatListenerFilesystem)
