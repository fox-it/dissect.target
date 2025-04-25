from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from dissect.target.plugins.os.windows import sru
from tests._utils import absolute_path

if TYPE_CHECKING:
    import pytest

    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_sru_plugin(target_win: Target, fs_win: VirtualFilesystem, caplog: pytest.LogCaptureFixture) -> None:
    srudb = absolute_path("_data/plugins/os/windows/sru/SRUDB.dat")

    fs_win.map_file("Windows/System32/sru/SRUDB.dat", srudb)

    target_win.add_plugin(sru.SRUPlugin)

    assert len(list(target_win.sru())) == 220
    assert len(list(target_win.sru.application())) == 203
    assert len(list(target_win.sru.network_connectivity())) == 3
    assert len(list(target_win.sru.sdp_volume_provider())) == 6
    assert len(list(target_win.sru.sdp_physical_disk_provider())) == 3
    assert len(list(target_win.sru.sdp_cpu_provider())) == 3

    caplog.clear()
    with caplog.at_level(logging.WARNING, target_win.log.name):
        assert list(target_win.sru.vfu()) == []
        assert "Table not found: vfu" in caplog.text
