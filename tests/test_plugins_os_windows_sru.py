import pytest

from dissect.target.plugins.os.windows import sru

from ._utils import absolute_path


def test_sru_plugin(target_win, fs_win):
    srudb = absolute_path("data/SRUDB.dat")

    fs_win.map_file("Windows/System32/sru/SRUDB.dat", srudb)

    target_win.add_plugin(sru.SRUPlugin)

    assert len(list(target_win.sru())) == 220
    assert len(list(target_win.sru.application())) == 203
    assert len(list(target_win.sru.network_connectivity())) == 3
    assert len(list(target_win.sru.sdp_volume_provider())) == 6
    assert len(list(target_win.sru.sdp_physical_disk_provider())) == 3
    assert len(list(target_win.sru.sdp_cpu_provider())) == 3

    with pytest.raises(ValueError) as e:
        list(target_win.sru.vfu())

    assert str(e.value) == "Table not found: vfu"
