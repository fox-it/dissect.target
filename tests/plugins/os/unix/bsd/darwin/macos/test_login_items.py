from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.login_items import LoginItemsPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            ("BackgroundItems-v16.btm",),
            ("/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v16.btm",),
        ),
    ],
)
def test_login_items(
    names: tuple[str, ...],
    paths: tuple[str, ...],
    target_unix: Target,
    fs_unix: VirtualFilesystem,
) -> None:
    tz = timezone.utc
    user = UnixUserRecord(
        name="user",
        uid=501,
        gid=20,
        home="/Users/user",
        shell="/bin/zsh",
    )
    target_unix.users = lambda: [user]
    stat_results = []
    entries = []

    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/{name}")
        fs_unix.map_file(path, data_file)
        entry = fs_unix.get(path)
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199
        stat_results.append(stat_result)
        entries.append(entry)

    with (
        patch.object(entries[0], "stat", return_value=stat_results[0]),
    ):
        target_unix.add_plugin(LoginItemsPlugin)

        results = list(target_unix.login_items())
        results.sort(key=lambda r: (r.source, getattr(r, "plist_path", "")))

        assert len(results) == 4

        assert results[0].associatedBundleIdentifiers is None
        assert isinstance(results[0].bookmark, (bytes, bytearray))
        assert results[0].bundleIdentifier == "com.microsoft.VSCode"
        assert results[0].container is None
        assert results[0].designatedRequirement == (
            'identifier "com.microsoft.VSCode" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] '  # noqa E501
            "/* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = UBF8T346G9"  # noqa E501
        )
        assert results[0].developerName is None
        assert results[0].login_item_disposition == 3
        assert results[0].executableModificationDate == datetime(1970, 1, 1, 0, 0, tzinfo=tz)
        assert results[0].executablePath is None
        assert results[0].flags == 0
        assert results[0].generation == 0
        assert results[0].identifier == "2.com.microsoft.VSCode"
        assert isinstance(results[0].lightweightRequirement, (bytes, bytearray))
        assert results[0].modificationDate == datetime(1995, 4, 29, 15, 46, 38, tzinfo=tz)
        assert results[0].name == "Visual Studio Code.app"
        assert results[0].programArguments is None
        assert results[0].sha256 is None
        assert results[0].teamIdentifier == "UBF8T346G9"
        assert results[0].login_item_type == 2
        assert results[0].url == "file:///Applications/Visual%20Studio%20Code.app/"
        assert results[0].uuid == "6f541698-5211-4cf2-95b7-e97534baee39"
        assert results[0].plist_path == "itemsByUserIdentifier/5C6F7FDD-02B2-498E-97B6-DE77293A8E90[0]"
        assert results[0].source == "/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v16.btm"

        assert results[1].generation == 2
        assert results[1].background_app_refresh_load_count == 17
        assert results[1].launch_services_items_imported
        assert results[1].service_management_login_items_migrated
        assert results[1].plist_path == "userSettingsByUserIdentifier/5C6F7FDD-02B2-498E-97B6-DE77293A8E90"
        assert results[1].source == "/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v16.btm"

        assert results[2].generation == 0
        assert results[2].background_app_refresh_load_count == 13
        assert not results[2].launch_services_items_imported
        assert not results[2].service_management_login_items_migrated
        assert results[2].plist_path == "userSettingsByUserIdentifier/FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000"
        assert results[2].source == "/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v16.btm"

        assert results[3].generation == 14
        assert results[3].background_app_refresh_load_count == 41
        assert not results[3].launch_services_items_imported
        assert results[3].service_management_login_items_migrated
        assert results[3].plist_path == "userSettingsByUserIdentifier/FFFFEEEE-DDDD-CCCC-BBBB-AAAAFFFFFFFE"
        assert results[3].source == "/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v16.btm"
