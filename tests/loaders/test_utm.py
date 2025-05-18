from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, call, patch

from dissect.target.loaders.utm import UtmLoader
from tests._utils import mkdirs

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


@patch("dissect.target.loaders.utm.container")
def test_utm_loader(container: MagicMock, target_bare: Target, tmp_path: Path) -> None:
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

    utm_path = root / "Test.utm"
    assert UtmLoader.detect(utm_path)

    utm_loader = UtmLoader(utm_path)
    utm_loader.map(target_bare)

    assert len(target_bare.disks) == 1
    assert container.open.mock_calls == [call(root.resolve() / "Test.utm" / "Data" / "Test.qcow2")]
