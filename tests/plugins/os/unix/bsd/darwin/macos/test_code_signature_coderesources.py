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
                "EndpointSecurity",
                "MobileDeviceUpdater",
                "AudioDMAController_T8140",
            ),
            (
                "/System/Library/Extensions/AppleUSBHostS5L8930X.kext/Contents/_CodeSignature/CodeResources",
                "/System/Library/CoreServices/FileProvider-Feedback.app/Contents/_CodeSignature/CodeResources",
                "/System/Library/Extensions/AppleUSBEthernet.kext/Contents/_CodeSignature/CodeResources",
                "/System/Library/Extensions/EndpointSecurity.kext/Contents/_CodeSignature/CodeResources",
                "/System/Library/PrivateFrameworks/MobileDevice.framework/Versions/A/Resources/MobileDeviceUpdater.app/Contents/_CodeSignature/CodeResources",
                "/System/Library/Extensions/AudioDMAController_T8140.kext/Contents/_CodeSignature/CodeResources",
            ),
        )
    ],
)
def test_code_signature_coderesources(
    names: tuple[str, ...], paths: tuple[str, ...], target_unix: Target, fs_unix: VirtualFilesystem
) -> None:
    stat_results = []
    entries = []
    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/code_signature/{name}")
        fs_unix.map_file(f"{path}", data_file)
        entry = fs_unix.get(f"{path}")
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199
        stat_results.append(stat_result)
        entries.append(entry)

    with (
        patch.object(entries[0], "stat", return_value=stat_results[0]),
        patch.object(entries[1], "stat", return_value=stat_results[1]),
        patch.object(entries[2], "stat", return_value=stat_results[2]),
    ):
        target_unix.add_plugin(CodeSignatureCodeResourcesPlugin)

        results = list(target_unix.code_signature_coderesources())
        results.sort(key=lambda r: (r.source, getattr(r, "plist_path", "")))

        assert len(results) == 294

        assert results[0].omit
        assert results[0].weight == 20.0
        assert results[0].plist_path == "rules/^.*"
        assert (
            results[0].source
            == "/System/Library/CoreServices/FileProvider-Feedback.app/Contents/_CodeSignature/CodeResources"
        )

        assert results[3].cdhash == "\x18\udc8f\x03\x1f\udcb2f(\udcafD.F\udcdbK\udcc05\udc91B\x1f\x06\udca9"
        assert results[3].requirement == 'identifier "com.apple.AppleUSBEthernet_kasan" and anchor apple'
        assert results[3].plist_path == "files2/macOS/AppleUSBEthernet_kasan"
        assert (
            results[3].source
            == "/System/Library/Extensions/AppleUSBEthernet.kext/Contents/_CodeSignature/CodeResources"
        )

        assert results[7].cdhash == "B\udcd5uȈ\udcf1K\x03qd\udce6\udcf2T4L\udc95\udcc4\udce0\x06\udc9f"
        assert results[7].requirement == 'identifier "com.apple.AppleUSBHostS5L8930X_kasan" and anchor apple'
        assert results[7].plist_path == "files2/macOS/AppleUSBHostS5L8930X_kasan"
        assert (
            results[7].source
            == "/System/Library/Extensions/AppleUSBHostS5L8930X.kext/Contents/_CodeSignature/CodeResources"
        )

        assert results[13].nested
        assert results[13].weight == 0.0
        assert (
            results[13].plist_path
            == "rules2/^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/"  # noqa E501
        )
        assert (
            results[13].source
            == "/System/Library/Extensions/AudioDMAController_T8140.kext/Contents/_CodeSignature/CodeResources"
        )

        assert (
            results[17].hash2
            == "yϑ\udcc9rl>h%\udcbek\udccf{\udca5E\udc90\udcdf-\x00R\udcac\udcd8\udcc3m.\udce6,(;\udce1v\x00"
        )
        assert results[17].optional is None
        assert results[17].plist_path == "files2/version.plist"
        assert (
            results[17].source
            == "/System/Library/Extensions/EndpointSecurity.kext/Contents/_CodeSignature/CodeResources"
        )

        assert results[29].optional
        assert results[29].weight == 1000.0
        assert results[29].plist_path == "rules2/^Resources/.*\\.lproj/"
        assert (
            results[29].source
            == "/System/Library/Extensions/EndpointSecurity.kext/Contents/_CodeSignature/CodeResources"
        )

        assert results[153].hash == "\udcd7p\udcdfĲ\udcc2\x0e\udcc9\x161ř{\udca3\udc89\udce7M\udcd7\udcf3Q"
        assert results[153].optional
        assert results[153].plist_path == "files/Resources/zh_TW.lproj/MobileDeviceUpdateController.strings"
        assert (
            results[153].source
            == "/System/Library/PrivateFrameworks/MobileDevice.framework/Versions/A/Resources/MobileDeviceUpdater.app/Contents/_CodeSignature/CodeResources"  # noqa E501
        )
