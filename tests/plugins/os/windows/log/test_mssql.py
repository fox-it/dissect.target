from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.log.mssql import MssqlPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


def test_mssql_errorlog(target_win_users: Target, hive_hklm: VirtualHive, fs_win: Filesystem) -> None:
    errorlog_file = absolute_path("_data/plugins/os/windows/log/mssql/errorlog")
    target_errorlog_name = "/sysvol/Temp/MSSQL/Log/ERRORLOG"

    _, _, map_path = target_errorlog_name.partition("sysvol/")
    fs_win.map_file(map_path, errorlog_file)

    errorlog_name = "SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQL69.MyInstance\\SQLServerAgent"
    errorlog_key = VirtualKey(hive_hklm, errorlog_name)
    hive_hklm.map_key(errorlog_name, errorlog_key)
    errorlog_key.add_value(
        "ErrorLogFile", VirtualValue(hive_hklm, "ErrorLogFile", "C:\\Temp\\MSSQL\\Log\\SQLAGENT.OUT")
    )

    datapath_name = "SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQL69.MyInstance\\MSSQLServer"
    datapath_key = VirtualKey(hive_hklm, datapath_name)
    hive_hklm.map_key(datapath_name, datapath_key)
    datapath_key.add_value("DefaultData", VirtualValue(hive_hklm, "DefaultData", "C:\\Temp\\MSSQL\\Data"))

    target_win_users.add_plugin(MssqlPlugin)
    records = list(target_win_users.mssql())
    assert len(records) == 101

    record = records[51]
    assert str(record.ts) == "2024-04-08 12:16:41.190000+00:00"
    assert record.instance == "MSSQL69.MyInstance"
    assert record.process == "Server"
    assert record.message.startswith("The SQL Server Network Interface library could not register")
    assert record.path == "C:\\Temp\\MSSQL\\Log\\ERRORLOG"
