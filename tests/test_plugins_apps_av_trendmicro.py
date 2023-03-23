from flow.record.fieldtypes import datetime as dt

from dissect.target.plugins.apps.av.trendmicro import (
    TrendMicroPlugin,
    TrendMicroWFFirewallRecord,
    TrendMicroWFLogRecord,
)

from ._utils import absolute_path


def test_trendmicro_plugin_worryfree_firewall(target_win, fs_win):
    log_file = absolute_path("data/apps/av/trendmicro/firewall.log")
    fs_win.map_file("Program Files (x86)/Trend Micro/Security Agent/PFW/PfwLog_20230101.dat", log_file)
    target_win.add_plugin(TrendMicroPlugin)
    records = list(target_win.trendmicro.wffirewall())
    assert len(records) == 1
    assert isinstance(records[0], type(TrendMicroWFFirewallRecord()))
    assert records[0].ts == dt("2023-03-14T09:42:55Z")
    assert str(records[0].local_ip) == "127.0.0.1"
    assert str(records[0].remote_ip) == "255.255.255.255"
    assert records[0].direction == "in"
    assert records[0].port == 444
    assert str(records[0].path) == "C:\\WINDOWS\\SYSTEM32\\SVCHOST.EXE"
    assert records[0].description == "SecurityLevelDrop"


def test_trendmicro_plugin_worryfree_log(target_win, fs_win):
    log_file = absolute_path("data/apps/av/trendmicro/pccnt35.log")
    fs_win.map_file("Program Files (x86)/Trend Micro/Security Agent/Misc/pccnt35.log", log_file)
    target_win.add_plugin(TrendMicroPlugin)
    records = list(target_win.trendmicro.wflogs())
    assert len(records) == 1
    assert isinstance(records[0], type(TrendMicroWFLogRecord()))
    assert records[0].ts == dt("2023-03-10T15:06:19Z")
    assert records[0].threat == "Eicar_test_file"
    assert str(records[0].path) == "C:\\Users\\admin\\Desktop\\test\\eicarcom2.zip"
    assert records[0].lineno == 0
