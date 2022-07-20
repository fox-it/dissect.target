from dissect.target.plugins.os.windows import ual

from ._utils import absolute_path


def test_ual_plugin(target_win, fs_win, tmpdir_name):

    ual_dir = absolute_path("data/ual/")

    fs_win.map_dir("Windows/System32/LogFiles/Sum", ual_dir)

    target_win.add_plugin(ual.UalPlugin)

    client_access_records = list(target_win.ual.client_access())
    assert len(client_access_records) == 106

    system_identity_records = list(target_win.ual.system_identities())
    assert len(system_identity_records) == 2

    role_access_records = list(target_win.ual.role_access())
    assert len(role_access_records) == 3

    virtual_machines_records = list(target_win.ual.virtual_machines())
    assert len(virtual_machines_records) == 0

    domains_seen_records = list(target_win.ual.domains_seen())
    assert len(domains_seen_records) == 12

    ual_all_records = list(target_win.ual.get_all_records())
    assert len(ual_all_records) == 123
