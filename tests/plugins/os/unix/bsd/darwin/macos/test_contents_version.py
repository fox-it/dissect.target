from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.contents_version import (
    ContentsVersionPlugin,
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
    stat_results = []
    entries = []
    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/contents_version/{name}")
        fs_unix.map_file(path, data_file)
        entry = fs_unix.get(path)
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199
        stat_results.append(stat_result)
        entries.append(entry)

    with (
        patch.object(entries[0], "stat", return_value=stat_results[0]),
        patch.object(entries[1], "stat", return_value=stat_results[1]),
        patch.object(entries[2], "stat", return_value=stat_results[2]),
    ):
        target_unix.add_plugin(ContentsVersionPlugin)

        results = list(target_unix.contents_version())
        results.sort(key=lambda r: r.source)

        assert len(results) == 3

        assert results[0].build_alias_of == "Ensemble"
        assert results[0].build_version == "1983"
        assert results[0].cf_bundle_short_version_string == "1.0"
        assert results[0].cf_bundle_version == "174.4.1"
        assert results[0].project_name == "Ensemble_executables"
        assert results[0].source_version == "174004001000000"
        assert results[0].source == "/System/Library/CoreServices/UniversalControl.app/Contents/version.plist"

        assert results[1].build_version == "100"
        assert results[1].cf_bundle_short_version_string == "1.0"
        assert results[1].cf_bundle_version == "1"
        assert results[1].project_name == "MobileBluetooth"
        assert results[1].source_version == "194026001000001"
        assert (
            results[1].source == "/System/Library/Frameworks/IOBluetoothUI.framework/Versions/A/Resources/version.plist"
        )

        assert results[2].build_alias_of == "SwiftUI"
        assert results[2].build_version == "12"
        assert results[2].cf_bundle_short_version_string == "7.4.27"
        assert results[2].cf_bundle_version == "7.4.27"
        assert results[2].project_name == "SwiftUICore"
        assert results[2].source_version == "7004027000000"
        assert (
            results[2].source == "/System/Library/Frameworks/SwiftUICore.framework/Versions/A/Resources/version.plist"
        )
