from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.logs.wifi_log import WifiLogPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "wifi.log",
    ],
)
def test_wifi_log(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    tz = timezone.utc
    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/logs/{test_file}")
    fs_unix.map_file(f"/var/log/{test_file}", data_file)

    entry = fs_unix.get(f"/var/log/{test_file}")
    stat_result = entry.stat()
    stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(WifiLogPlugin)

        results = list(target_unix.wifi_log())
        assert len(results) == 2

        assert results[0].ts == datetime(2023, 5, 4, 4, 23, 16, 776000, tzinfo=tz)
        assert results[0].host == "[airport]/114"
        assert (
            results[0].message
            == "@[5.319676] (configdIODriverInterface.m:401) dq:'com.apple.main-thread'/tid[0x39e] FreedDeviceNodeListManager initialized, list[0xb2cd122e0] lock[0xb2d0f8380]"  # noqa: E501
        )
        assert results[0].source == "/var/log/wifi.log"

        assert results[1].ts == datetime(2023, 5, 4, 4, 23, 16, 774000, tzinfo=tz)
        assert results[1].host == "<airport[114]>"
        assert results[1].message == "configdStart: ****** [AirPort logger started] ******"
        assert results[1].source == "/var/log/wifi.log"
