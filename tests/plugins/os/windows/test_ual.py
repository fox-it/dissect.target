from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.windows import ual
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_ual_plugin(target_win: Target, fs_win: VirtualFilesystem) -> None:
    ual_dir = absolute_path("_data/plugins/os/windows/ual")

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

    ual_all_records = list(target_win.ual())
    assert len(ual_all_records) == 123
