from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, call, patch

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
def test_target_open(opener: Callable[[str | Path], Target], monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that we correctly use ``AdbLoader`` when opening a ``Target``."""
    with monkeypatch.context() as m:
        if "dissect.target.loaders.adb" in sys.modules:
            m.delitem(sys.modules, "dissect.target.loaders.adb")
        if "dissect.target.filesystems.adb" in sys.modules:
            m.delitem(sys.modules, "dissect.target.filesystems.adb")

        mock_adbutils = MagicMock()
        mock_device = MagicMock()
        mock_client = MagicMock()
        mock_client.device.return_value = mock_device
        mock_device.get_features.return_value = "shell_v2"

        mock_adbutils.AdbClient.return_value = mock_client
        m.setitem(sys.modules, "adbutils", mock_adbutils)

        from dissect.target.loaders.adb import AdbLoader

        path = "adb://?dialect=linux"
        with patch("dissect.target.target.Target.apply"):
            target = opener(path)
            assert isinstance(target._loader, AdbLoader)
            assert target.path == Path()


def test_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test the ADB loader."""
    with monkeypatch.context() as m:
        if "dissect.target.loaders.adb" in sys.modules:
            m.delitem(sys.modules, "dissect.target.loaders.adb")
        if "dissect.target.filesystems.adb" in sys.modules:
            m.delitem(sys.modules, "dissect.target.filesystems.adb")

        mock_adbutils = MagicMock()
        mock_device = MagicMock()
        mock_client = MagicMock()
        mock_client.device.return_value = mock_device
        mock_device.get_features.return_value = "shell_v2"

        mock_adbutils.AdbClient.return_value = mock_client
        m.setitem(sys.modules, "adbutils", mock_adbutils)

        from dissect.target.filesystems.adb import AdbFilesystem
        from dissect.target.loader import open as loader_open
        from dissect.target.loaders.adb import AdbLoader

        loader = loader_open("adb://?dialect=linux")
        assert isinstance(loader, AdbLoader)

        t = Target()
        loader.map(t)

        assert len(t.filesystems) == 1
        assert isinstance(t.filesystems[0], AdbFilesystem)
        assert mock_adbutils.AdbClient.call_args == call("127.0.0.1", 5037)
