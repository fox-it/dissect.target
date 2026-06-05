from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.resources_info_strings import ResourcesInfoStringsPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            ("WiFiAgent.strings", "OSvKernDSPLib.strings"),
            (
                "/System/Library/CoreServices/WiFiAgent.app/Contents/Resources/InfoPlist.strings",
                "/System/Library/Extensions/OSvKernDSPLib.kext/Contents/Resources/InfoPlist.strings",
            ),
        )
    ],
)
def test_resources_info_strings(
    names: tuple[str, ...], paths: tuple[str, ...], target_unix: Target, fs_unix: VirtualFilesystem
) -> None:
    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/resources_info_strings/{name}")
        fs_unix.map_file(f"{path}", data_file)

    target_unix.add_plugin(ResourcesInfoStringsPlugin)

    results = list(target_unix.resources_info_strings())
    results.sort(key=lambda r: (r.source, getattr(r, "plist_path", "")))
    assert len(results) == 2

    assert results[0].cf_bundle_name == "WiFiAgent"
    assert results[0].cf_bundle_display_name == "Wi-Fi"
    assert results[0].cf_bundle_identifier is None
    assert results[0].cf_bundle_version is None
    assert results[0].cf_bundle_package_type is None
    assert results[0].cf_bundle_signature is None
    assert results[0].cf_bundle_executable is None
    assert results[0].cf_bundle_document_types == []
    assert results[0].cf_bundle_short_version_string is None
    assert results[0].ls_minimum_system_version is None
    assert results[0].ns_human_readable_copyright is None
    assert results[0].ns_main_nib_file is None
    assert results[0].ns_principal_class is None
    assert results[0].source == "/System/Library/CoreServices/WiFiAgent.app/Contents/Resources/InfoPlist.strings"

    assert results[1].cf_bundle_name is None
    assert results[1].cf_bundle_display_name is None
    assert results[1].cf_bundle_identifier is None
    assert results[1].cf_bundle_version is None
    assert results[1].cf_bundle_package_type is None
    assert results[1].cf_bundle_signature is None
    assert results[1].cf_bundle_executable is None
    assert results[1].cf_bundle_document_types == []
    assert results[1].cf_bundle_short_version_string is None
    assert results[1].ls_minimum_system_version is None
    assert results[1].ns_human_readable_copyright == "Copyright © 2004 Apple Inc. All rights reserved."
    assert results[1].ns_main_nib_file is None
    assert results[1].ns_principal_class is None
    assert results[1].source == "/System/Library/Extensions/OSvKernDSPLib.kext/Contents/Resources/InfoPlist.strings"
