from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.apps.remoteaccess.splashtop import SplashtopPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


SPLASHTOP_LOG_PATH = "Program Files (x86)/Splashtop/Splashtop Remote/Server/log/SPLog.txt"


@pytest.fixture
def target_splashtop(target_win_users: Target, fs_win: VirtualFilesystem) -> Iterator[Target]:
    fs_win.map_file(
        SPLASHTOP_LOG_PATH,
        absolute_path("_data/plugins/apps/remoteaccess/splashtop/SPLog.txt"),
    )

    # The Splashtop plugin uses a year rollover helper which uses the modification time of a file to determine
    # the starting year
    # A new source checkout would result in different modification timestamps, so mock it to be in 2025
    entry = fs_win.get(SPLASHTOP_LOG_PATH)
    stat_result = entry.stat()
    stat_result.st_mtime = 1735732800

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result
        target_win_users.add_plugin(SplashtopPlugin)
        yield target_win_users


def test_splashtop_plugin_log(target_splashtop: Target) -> None:
    records = list(target_splashtop.splashtop.logs())
    assert len(records) == 384

    assert records[-1].ts == datetime(2025, 7, 14, 15, 15, 38, 194000, tzinfo=timezone.utc)
    assert records[-1].message == "SM_03280[Network] [LAN-S][Server] client connected from 10.199.5.134 (2), 288"
    assert records[-1].source == f"sysvol/{SPLASHTOP_LOG_PATH}"


def test_splashtop_plugin_filetransfer(target_splashtop: Target) -> None:
    records = list(target_splashtop.splashtop.filetransfer())
    assert len(records) == 1

    assert records[0].ts == datetime(2025, 7, 14, 15, 17, 30, 766000, tzinfo=timezone.utc)
    assert (
        records[0].message
        == 'SM_03280[FTCnnel] OnUploadFileCPRequest 1, 1 =>{"fileID":"353841253","fileName":"NOTE.txt","fileSize":"34","remotesessionFTC":1,"request":"uploadFile"}'  # noqa: E501
    )
    assert records[0].source == f"sysvol/{SPLASHTOP_LOG_PATH}"
    assert records[0].filename == "NOTE.txt"
