from flow.record.fieldtypes import datetime as dt

from dissect.target.plugins.apps.av.mcafee import McAfeeMscFirewallRecord, McAfeePlugin

from ._utils import absolute_path


def test_mcafee_plugin_log(target_win, fs_win):
    log_dir = absolute_path("data/apps/av/mcafee")
    fs_win.map_dir("ProgramData/McAfee/MSC/Logs", log_dir)

    target_win.add_plugin(McAfeePlugin)

    records = list(target_win.mcafee.msc())
    assert len(records) == 2
    for record in records:
        if isinstance(record, type(McAfeeMscFirewallRecord())):
            assert record.ip == "127.0.0.1"
            assert record.protocol == "TCP"
            assert record.port == 54996
            assert record.ts == dt("2023-03-07T10:32:34Z")
            assert record.fkey == "{C492A216-EFFC-4DAE-BE5E-2F5E064594C9}"
            assert (
                record.message
                == "The PC 127.0.0.1 tried to connect to TCP port 54996 on your PC without your permission."
            )
            assert record.keywords == "127.0.0.1,127.0.0.1,TCP port 54996"

        else:
            assert record.threat == "EICAR test file"
            assert record.ts == dt("2023-03-07T10:55:18Z")
            assert record.fkey == "{37E1F90E-471D-40D3-9FAA-37BE30C5B4AA}"
            assert (
                record.message
                == "Status Quarantined Scan type Custom  We found one or several threats on your PC. "
                + "Threat name EICAR test file File C:\\Users\\admin\\Desktop\\eicar.com"
            )
            assert record.keywords == "Custom,EICAR test file,Quarantined"
