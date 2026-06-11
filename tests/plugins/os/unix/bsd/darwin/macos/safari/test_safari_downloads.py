from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.safari.safari_downloads import SafariDownloadsPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "Downloads.plist",
    ],
)
def test_safari_downloads(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    user = UnixUserRecord(
        name="user",
        uid=501,
        gid=20,
        home="/Users/user",
        shell="/bin/zsh",
    )
    target_unix.users = lambda: [
        user,
    ]

    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/safari/{test_file}")
    fs_unix.map_file(f"Users/user/Library/Safari/{test_file}", data_file)

    target_unix.add_plugin(SafariDownloadsPlugin)

    results = list(target_unix.safari_downloads())

    assert len(results) == 2

    assert results[0].download_entry_progress_total_to_load == 370221
    assert results[0].download_entry_progress_bytes_so_far == 370221
    assert results[0].download_entry_path == "/Users/user/Downloads/another_apple.jpg"
    assert results[0].download_entry_date_added == datetime(2026, 6, 11, 7, 47, 5, 68034, tzinfo=timezone.utc)
    assert not results[0].download_entry_remove_when_done
    assert not results[0].download_entry_should_use_request_url_as_origin_url_if_necessary
    assert results[0].download_entry_profile_uuid_string == "DefaultProfile"
    assert results[0].download_entry_date_finished == datetime(2026, 6, 11, 7, 47, 15, 349867, tzinfo=timezone.utc)
    assert results[0].download_entry_url == (
        "https://images.unsplash.com/photo-1568702846914-96b305d2aaeb"
        "?ixlib=rb-4.1.0&q=85&fm=jpg&crop=entropy&cs=srgb"
        "&dl=an_vision-gDPaDDy6_WE-unsplash.jpg"
    )
    assert results[0].download_entry_sandbox_identifier == "1109426B-5B25-49B3-9FE7-C27B77F36576"
    assert results[0].download_entry_bookmark_blob is not None
    assert isinstance(results[0].download_entry_bookmark_blob, (bytes, bytearray))
    assert results[0].download_entry_identifier == "AD6033B8-86AA-4CAC-9398-70C180C0FA30"
    assert results[0].source == "/Users/user/Library/Safari/Downloads.plist"

    assert results[1].download_entry_progress_total_to_load == 1173811
    assert results[1].download_entry_progress_bytes_so_far == 1173811
    assert results[1].download_entry_path == "/Users/user/Documents/apple.jpg"
    assert results[1].download_entry_date_added == datetime(2026, 6, 11, 7, 46, 42, 238320, tzinfo=timezone.utc)
    assert not results[1].download_entry_remove_when_done
    assert not results[1].download_entry_should_use_request_url_as_origin_url_if_necessary
    assert results[1].download_entry_profile_uuid_string == "DefaultProfile"
    assert results[1].download_entry_date_finished == datetime(2026, 6, 11, 7, 46, 50, 126514, tzinfo=timezone.utc)
    assert results[1].download_entry_url == (
        "https://images.unsplash.com/photo-1630563451961-ac2ff27616ab?ixlib=rb-4.1.0&q=85&fm=jpg&crop=entropy&cs=srgb&dl=tobi-zLCR7RsxYGs-unsplash.jpg"
    )
    assert results[1].download_entry_sandbox_identifier == "95FB1F71-C489-4A07-AFB9-509F4B2BC105"
    assert results[1].download_entry_bookmark_blob is not None
    assert isinstance(results[1].download_entry_bookmark_blob, (bytes, bytearray))
    assert results[1].download_entry_identifier == "BD390ED6-0E4C-4B25-ACB1-E50F9E2B2347"
    assert results[1].source == "/Users/user/Library/Safari/Downloads.plist"
