from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flow.record.fieldtypes import datetime as dt

from dissect.target.plugins.os.unix.bsd.darwin.macos.installhistory import (
    InstallHistoryPlugin,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture
def target_macos_installhistory(target_macos: Target, fs_macos: VirtualFilesystem) -> Target:
    fs_macos.map_file(
        "/Library/Receipts/InstallHistory.plist",
        absolute_path("_data/plugins/os/unix/bsd/darwin/macos/installhistory/InstallHistory.plist"),
    )
    target_macos.add_plugin(InstallHistoryPlugin)
    return target_macos


def test_unix_bsd_darwin_macos_install_history(target_macos_installhistory: Target) -> None:
    records = list(target_macos_installhistory.install_history())

    assert len(records) == 6

    # macOS system update: no contentType, no packageIdentifiers
    r = records[0]
    assert r.ts == dt("2025-07-25T13:09:46+00:00")
    assert r.name == "macOS 15.5"
    assert r.version == "15.5"
    assert r.process == "softwareupdated"
    assert r.content_type is None
    assert r.package_ids == []
    assert str(r.source) == "/Library/Receipts/InstallHistory.plist"

    # XProtect: contentType=config-data, single packageIdentifier
    r = records[1]
    assert r.ts == dt("2025-07-30T15:24:26+00:00")
    assert r.name == "XProtectPlistConfigData"
    assert r.content_type == "config-data"
    assert r.package_ids == ["com.apple.pkg.XProtectPlistConfigData_10_15.16U4380"]

    # Command Line Tools: 9 packageIdentifiers
    r = records[4]
    assert r.name == "Command Line Tools for Xcode 26.0"
    assert r.content_type is None
    assert len(r.package_ids) == 9
    assert "com.apple.pkg.CLTools_Executables" in r.package_ids

    # Safari install
    r = records[5]
    assert r.name == "Safari"
    assert r.version == "26.0.1"
    assert r.package_ids == ["com.apple.pkg.Safari26.0.1SequoiaAuto"]
