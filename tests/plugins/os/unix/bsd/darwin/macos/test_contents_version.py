from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.contents_version import (
    MacOSContentsVersionPlugin,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            (
                "UniversalControl.plist",
                "IOBluetoothUI.plist",
                "SwiftUICore.plist",
            ),
            (
                "/System/Library/CoreServices/UniversalControl.app/Contents/version.plist",
                "/System/Library/Frameworks/IOBluetoothUI.framework/Versions/A/Resources/version.plist",
                "/System/Library/Frameworks/SwiftUICore.framework/Versions/A/Resources/version.plist",
            ),
        )
    ],
)
def test_contents_version(
    names: tuple[str, ...], paths: tuple[str, ...], target_unix: Target, fs_unix: VirtualFilesystem
) -> None:
    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/contents_version/{name}")
        fs_unix.map_file(path, data_file)
        entry = fs_unix.get(path)
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(MacOSContentsVersionPlugin)

        results = list(target_unix.contents_version())
        results.sort(key=lambda r: r.source)

        assert len(results) == 3

        assert results[0].BuildAliasOf == "Ensemble"
        assert results[0].BuildVersion == "1983"
        assert results[0].CFBundleShortVersionString == "1.0"
        assert results[0].CFBundleVersion == "174.4.1"
        assert results[0].ProjectName == "Ensemble_executables"
        assert results[0].SourceVersion == "174004001000000"
        assert results[0].source == "/System/Library/CoreServices/UniversalControl.app/Contents/version.plist"

        assert results[1].BuildVersion == "100"
        assert results[1].CFBundleShortVersionString == "1.0"
        assert results[1].CFBundleVersion == "1"
        assert results[1].ProjectName == "MobileBluetooth"
        assert results[1].SourceVersion == "194026001000001"
        assert (
            results[1].source == "/System/Library/Frameworks/IOBluetoothUI.framework/Versions/A/Resources/version.plist"
        )

        assert results[2].BuildAliasOf == "SwiftUI"
        assert results[2].BuildVersion == "12"
        assert results[2].CFBundleShortVersionString == "7.4.27"
        assert results[2].CFBundleVersion == "7.4.27"
        assert results[2].ProjectName == "SwiftUICore"
        assert results[2].SourceVersion == "7004027000000"
        assert (
            results[2].source == "/System/Library/Frameworks/SwiftUICore.framework/Versions/A/Resources/version.plist"
        )
