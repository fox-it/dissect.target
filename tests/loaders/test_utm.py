from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.utm import UtmLoader
from dissect.target.target import Target
from tests._utils import mkdirs

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def mock_utm_dir(tmp_path: Path) -> Path:
    dummy_plist = """<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>Drive</key>
        <array>
            <dict>
                <key>Identifier</key>
                <string>Test</string>
                <key>ImageName</key>
                <string>Test.qcow2</string>
                <key>ImageType</key>
                <string>Disk</string>
                <key>Interface</key>
                <string>IDE</string>
                <key>InterfaceVersion</key>
                <integer>1</integer>
                <key>ReadOnly</key>
                <false/>
            </dict>
        </array>
    </dict>
    </plist>
    """

    root = tmp_path
    mkdirs(root, ["Test.utm"])
    (root / "Test.utm" / "config.plist").write_text(textwrap.dedent(dummy_plist))

    return root / "Test.utm"


def test_target_open(mock_utm_dir: Path) -> None:
    """Test that we correctly use ``UtmLoader`` when opening a ``Target``."""
    with patch("dissect.target.loaders.utm.container.open"), patch("dissect.target.target.Target.apply"):
        for target in (Target.open(mock_utm_dir), next(Target.open_all(mock_utm_dir), None)):
            assert target is not None
            assert isinstance(target._loader, UtmLoader)
            assert target.path == mock_utm_dir


def test_loader(mock_utm_dir: Path) -> None:
    loader = loader_open(mock_utm_dir)
    assert isinstance(loader, UtmLoader)

    with patch("dissect.target.loaders.utm.container.open") as mock_container_open:
        t = Target()
        loader.map(t)

        assert len(t.disks) == 1
        mock_container_open.assert_called_with(mock_utm_dir / "Data" / "Test.qcow2")
