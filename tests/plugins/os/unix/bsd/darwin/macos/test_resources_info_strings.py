from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.resources_info_strings import MacOSResourcesInfoStringsPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            ("InfoPlist.strings",),
            ("/System/Library/Extensions/OSvKernDSPLib.kext/Contents/Resources/InfoPlist.strings",),
        )
    ],
)
def test_resources_info_strings(
    names: tuple[str, ...], paths: tuple[str, ...], target_unix: Target, fs_unix: VirtualFilesystem
) -> None:
    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/resources_info_strings/{name}")
        fs_unix.map_file(f"{path}", data_file)
        entry = fs_unix.get(f"{path}")
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(MacOSResourcesInfoStringsPlugin)

        results = list(target_unix.resources_info_strings())
        results.sort(key=lambda r: (r.source, getattr(r, "plist_path", "")))
        assert len(results) == 1

        assert results[0].NSHumanReadableCopyright == "Copyright © 2004 Apple Inc. All rights reserved."
        assert results[0].source == "/System/Library/Extensions/OSvKernDSPLib.kext/Contents/Resources/InfoPlist.strings"
