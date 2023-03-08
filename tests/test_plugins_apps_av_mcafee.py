from flow.record.fieldtypes import datetime as dt

from dissect.target.plugins.apps.av.mcafee import McAfeeMscLogRecord, McAfeePlugin

from ._utils import absolute_path


def test_mcafee_plugin_log(target_win, fs_win):
    log_dir = absolute_path("data/apps/av/mcafee")
    fs_win.map_dir("ProgramData/McAfee/MSC/Logs", log_dir)

    target_win.add_plugin(McAfeePlugin)

    records = list(target_win.mcafee.msc())
    assert len(records) == 2
    for record in records:
        assert isinstance(record, type(McAfeeMscLogRecord()))
        if record.threat is None:
            assert record.ip == "127.0.0.1"
            assert record.port == 54996
            assert record.ts == dt("2023-03-07T10:32:34Z")
        else:
            assert record.threat == "EICAR test file"
            assert record.ip is None
            assert record.port is None
            assert record.ts == dt("2023-03-07T10:55:18Z")
