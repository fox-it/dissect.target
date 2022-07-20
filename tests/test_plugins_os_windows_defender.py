from dissect.target.plugins.os.windows import defender

from ._utils import absolute_path


def test_defender_evtx_logs(target_win, fs_win, tmpdir_name):

    # map default log location to pass EvtxPlugin's compatibility check
    fs_win.map_dir("windows/system32/winevt/logs", tmpdir_name)

    log_file = absolute_path("data/defender-operational.evtx")
    fs_win.map_file("windows/system32/winevt/logs/Microsoft-Windows-Windows Defender%4Operational.evtx", log_file)

    target_win.add_plugin(defender.MicrosoftDefenderPlugin)

    records = list(target_win.defender.evtx())

    assert len(records) == 9

    # verify that all records have unique EventIDs
    assert len(list(r.EventID for r in records)) == 9
    assert {r.Provider_Name for r in records} == {"Microsoft-Windows-Windows Defender"}
    assert {r.Channel for r in records} == {"Microsoft-Windows-Windows Defender/Operational"}
    # Both informational records (no threat name) and detections are present
    assert {r.Threat_Name for r in records} == {None, "TrojanDropper:PowerShell/PowerSploit.S!MSR"}
