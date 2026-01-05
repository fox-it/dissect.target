from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

from dissect.target.exceptions import FilesystemError


def test_adb_filesystem(monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as m:
        if "dissect.target.filesystems.adb" in sys.modules:
            m.delitem(sys.modules, "dissect.target.filesystems.adb")

        mock_adbutils = MagicMock()
        mock_device = MagicMock()
        mock_client = MagicMock()
        mock_device.serial = "test-serial"
        mock_client.list.return_value = [mock_device]
        mock_client.device.return_value = mock_device
        mock_device.get_features.return_value = "shell_v1"

        mock_adbutils.AdbClient.return_value = mock_client
        m.setitem(sys.modules, "adbutils", mock_adbutils)

        from dissect.target.filesystems.adb import AdbFilesystem

        with pytest.raises(FilesystemError, match="Device does not support shell_v2 feature"):
            fs = AdbFilesystem("127.0.0.1", 5037, None, "linux")

        mock_device.get_features.return_value = "shell_v2"
        with pytest.raises(FilesystemError, match="Device with serial unknown-serial not found"):
            fs = AdbFilesystem("127.0.0.1", 5037, "unknown-serial", "linux")

        fs = AdbFilesystem("127.0.0.1", 5037, None, "linux")
        assert fs.device.serial == "test-serial"

        fs = AdbFilesystem("127.0.0.1", 5037, "test-serial", "linux")
        assert fs.device.serial == "test-serial"
