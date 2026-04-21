from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.contents_info import ContentsInfoPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            (
                "AppleEventLogHandler.plist",
                "UnmountAssistantAgent.plist",
                "AppleHPET.plist",
            ),
            (
                "/System/Library/Extensions/AppleEventLogHandler.kext/Contents/Info.plist",
                "/System/Library/CoreServices/UnmountAssistantAgent.app/Contents/Info.plist",
                "/System/Library/Extensions/AppleHPET.kext/Contents/Info.plist",
            ),
        )
    ],
)
def test_contents_info(
    names: tuple[str, ...], paths: tuple[str, ...], target_unix: Target, fs_unix: VirtualFilesystem
) -> None:
    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/contents_info/{name}")
        fs_unix.map_file(f"{path}", data_file)
        entry = fs_unix.get(f"{path}")
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(ContentsInfoPlugin)

        results = list(target_unix.contents_info())
        results.sort(key=lambda r: (r.source, getattr(r, "plist_path", "")))

        assert len(results) == 7

        assert results[0].BuildMachineOSBuild == "23A344017"
        assert results[0].CFBundleDevelopmentRegion == "English"
        assert results[0].CFBundleExecutable == "UnmountAssistantAgent"
        assert results[0].CFBundleIdentifier == "com.apple.UnmountAssistantAgent"
        assert results[0].CFBundleInfoDictionaryVersion == "6.0"
        assert results[0].CFBundleName == "UnmountAssistantAgent"
        assert results[0].CFBundlePackageType == "APPL"
        assert results[0].CFBundleShortVersionString == "5.0"
        assert results[0].CFBundleSignature == "????"
        assert results[0].CFBundleSupportedPlatforms == "['MacOSX']"
        assert results[0].CFBundleVersion == "5.0"
        assert results[0].DTCompiler == "com.apple.compilers.llvm.clang.1_0"
        assert results[0].DTPlatformBuild == ""
        assert results[0].DTPlatformName == "macosx"
        assert results[0].DTPlatformVersion == "26.4"
        assert results[0].DTSDKBuild == "25E222"
        assert results[0].DTSDKName == "macosx26.4.internal"
        assert results[0].DTXcode == "2630"
        assert results[0].DTXcodeBuild == "17E6107"
        assert results[0].LSMinimumSystemVersion == "26.4"
        assert results[0].LSUIElement
        assert results[0].NSPrincipalClass == "NSApplication"
        assert results[0].source == "/System/Library/CoreServices/UnmountAssistantAgent.app/Contents/Info.plist"

        assert results[4].BuildMachineOSBuild == "23A344017"
        assert results[4].CFBundleDevelopmentRegion == "English"
        assert results[4].CFBundleExecutable == "AppleHPET"
        assert results[4].CFBundleIdentifier == "com.apple.driver.AppleHPET"
        assert results[4].CFBundleInfoDictionaryVersion == "6.0"
        assert results[4].CFBundleName == "High Precision Event Timer Driver"
        assert results[4].CFBundlePackageType == "KEXT"
        assert results[4].CFBundleShortVersionString == "1.8"
        assert results[4].CFBundleSignature == "????"
        assert results[4].CFBundleSupportedPlatforms == "['MacOSX']"
        assert results[4].CFBundleVersion == "1.8"
        assert results[4].DTCompiler == "com.apple.compilers.llvm.clang.1_0"
        assert results[4].DTPlatformBuild == "25E245"
        assert results[4].DTPlatformName == "macosx"
        assert results[4].DTPlatformVersion == "26.4"
        assert results[4].DTSDKBuild == "25E245"
        assert results[4].DTSDKName == "macosx26.4.internal"
        assert results[4].DTXcode == "2630"
        assert results[4].DTXcodeBuild == "17E6107"
        assert results[4].LSMinimumSystemVersion == "26.4"
        assert results[4].NSHumanReadableCopyright == ("Copyright © 2005-2012 Apple Inc. All rights reserved.")
        assert results[4].OSBundleRequired == "Root"
        assert results[4].source == "/System/Library/Extensions/AppleHPET.kext/Contents/Info.plist"

        assert results[6].com_apple_iokit_IOACPIFamily == "1.1.0"
        assert results[6].com_apple_kpi_iokit == "9.0.0"
        assert results[6].com_apple_kpi_libkern == "9.0.0"
        assert results[6].com_apple_kpi_mach == "9.0.0"
        assert results[6].com_apple_kpi_unsupported == "9.0.0"
        assert results[6].plist_path == "OSBundleLibraries"
        assert results[6].source == "/System/Library/Extensions/AppleHPET.kext/Contents/Info.plist"
