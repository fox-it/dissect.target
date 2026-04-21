from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.code_signature_coderesources import (
    CodeSignatureCodeResourcesPlugin,
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
                "Host",
                "FileProvider",
                "Ethernet",
            ),
            (
                "/System/Library/Extensions/AppleUSBHostS5L8930X.kext/Contents/_CodeSignature/CodeResources",
                "/System/Library/CoreServices/FileProvider-Feedback.app/Contents/_CodeSignature/CodeResources",
                "/System/Library/Extensions/AppleUSBEthernet.kext/Contents/_CodeSignature/CodeResources",
            ),
        )
    ],
)
def test_code_signature_coderesources(
    names: tuple[str, ...], paths: tuple[str, ...], target_unix: Target, fs_unix: VirtualFilesystem
) -> None:
    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/code_signature/{name}")
        fs_unix.map_file(f"{path}", data_file)
        entry = fs_unix.get(f"{path}")
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(CodeSignatureCodeResourcesPlugin)

        results = list(target_unix.code_signature_coderesources())
        results.sort(key=lambda r: (r.source, getattr(r, "plist_path", "")))

        assert len(results) == 11

        assert results[0].omit
        assert results[0].weight == "20.0"
        assert results[0].plist_path == "rules/^.*"
        assert (
            results[0].source
            == "/System/Library/CoreServices/FileProvider-Feedback.app/Contents/_CodeSignature/CodeResources"
        )

        assert results[3].cdhash == "\x18\udc8f\x03\x1f\udcb2f(\udcafD.F\udcdbK\udcc05\udc91B\x1f\x06\udca9"
        assert results[3].requirement == 'identifier "com.apple.AppleUSBEthernet_kasan" and anchor apple'
        assert results[3].plist_path == "files2/MacOS/AppleUSBEthernet_kasan"
        assert (
            results[3].source
            == "/System/Library/Extensions/AppleUSBEthernet.kext/Contents/_CodeSignature/CodeResources"
        )

        assert results[7].cdhash == "B\udcd5uȈ\udcf1K\x03qd\udce6\udcf2T4L\udc95\udcc4\udce0\x06\udc9f"
        assert results[7].requirement == 'identifier "com.apple.AppleUSBHostS5L8930X_kasan" and anchor apple'
        assert results[7].plist_path == "files2/MacOS/AppleUSBHostS5L8930X_kasan"
        assert (
            results[7].source
            == "/System/Library/Extensions/AppleUSBHostS5L8930X.kext/Contents/_CodeSignature/CodeResources"
        )
