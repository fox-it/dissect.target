from __future__ import annotations

import logging
from collections import Counter
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest

from dissect.target.plugins.os.windows import sru
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_sru_plugin(target_win: Target, fs_win: VirtualFilesystem, caplog: pytest.LogCaptureFixture) -> None:
    srudb = absolute_path("_data/plugins/os/windows/sru/SRUDB.dat")

    fs_win.map_file("Windows/System32/sru/SRUDB.dat", srudb)

    target_win.add_plugin(sru.SRUPlugin)
    sru_records = list(target_win.sru())
    assert len(sru_records) == 220
    assert Counter(str(r.source) for r in sru_records) == {"c:\\Windows\\System32\\sru\\SRUDB.dat": 220}
    assert len(list(target_win.sru.application())) == 203
    assert len(list(target_win.sru.network_connectivity())) == 3
    assert len(list(target_win.sru.sdp_volume_provider())) == 6
    assert len(list(target_win.sru.sdp_physical_disk_provider())) == 3
    assert len(list(target_win.sru.sdp_cpu_provider())) == 3

    caplog.clear()
    with caplog.at_level(logging.WARNING, target_win.log.name):
        assert list(target_win.sru.vfu()) == []
        assert "Table not found: vfu" in caplog.text


def _sru_plugin(target_win: Target, columns: list[str]) -> sru.SRUPlugin:
    """Return an SRU plugin that reads one table with ``columns`` and a single row of ones."""
    plugin = sru.SRUPlugin(target_win)
    plugin._sru = Mock()
    plugin._sru.get_table.return_value = SimpleNamespace(columns=[SimpleNamespace(name=name) for name in columns])
    plugin._sru.get_table_entries.return_value = [dict.fromkeys(columns, 1)]
    return plugin


@pytest.mark.parametrize(
    ("table_name", "record_type", "columns", "fields"),
    [
        (
            "network_data",
            sru.NetworkDataRecord,
            ["InterfaceLuid", "L2ProfileId", "L2ProfileFlags", "BytesSent", "BytesRecvd", "WakeCount"],
            ["wake_count"],
        ),
        (
            "push_notifications",
            sru.PushNotificationRecord,
            ["NotificationType", "PayloadSize", "NetworkType", "ConnectionType"],
            ["connection_type"],
        ),
        (
            "energy_usage_lt",
            sru.EnergyUsageLTRecord,
            ["ActiveAcTime", "CycleCount", "ConfigurationHash", "BatteryCount", "BatteryChargeLimited"],
            ["battery_count", "battery_charge_limited"],
        ),
    ],
)
def test_sru_columns_added_in_windows_11(
    target_win: Target, table_name: str, record_type: sru.SRURecord, columns: list[str], fields: list[str]
) -> None:
    """Test that the SRU tables with columns added in Windows 11 are read instead of raising a ``TypeError``."""
    plugin = _sru_plugin(target_win, ["AutoIncId", "TimeStamp", "AppId", "UserId", *columns])

    records = list(plugin.read_records(table_name, record_type))

    assert len(records) == 1
    assert all(getattr(records[0], field) == 1 for field in fields)
