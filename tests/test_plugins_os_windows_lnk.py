from flow.record.fieldtypes import datetime

from dissect.target.plugins.os.windows.lnk import LnkPlugin, LnkRecord

from ._utils import absolute_path


def test_lnk(target_win, fs_win):
    lnk_file = absolute_path("data/plugins/os/windows/lnk/pestudio.lnk")
    fs_win.map_file("Users/pestudio.lnk", lnk_file)

    target_win.add_plugin(LnkPlugin)

    records = list(target_win.lnk(None))

    assert len(records) == 1
    assert isinstance(records[0], type(LnkRecord()))
    assert str(records[0].lnk_path) == "sysvol/users/pestudio.lnk"
    assert records[0].lnk_name is None
    assert str(records[0].lnk_relativepath) == ".\\pestudio.exe"
    assert str(records[0].lnk_workdir) == "C:\\Program Files\\pestudio"
    assert records[0].lnk_arguments is None
    assert records[0].lnk_iconlocation is None
    assert records[0].local_base_path == "C:\\Program Files\\pestudio\\pestudio.exe"
    assert records[0].common_path_suffix == ""
    assert records[0].lnk_net_name is None
    assert records[0].lnk_device_name is None
    assert str(records[0].lnk_full_path) == "C:\\Program Files\\pestudio\\pestudio.exe"
    assert records[0].machine_id == "desktop-i2purd1"
    assert records[0].target_mtime == datetime("2021-10-09T07:24:42+00:00")
    assert records[0].target_atime == datetime("2021-10-16T15:26:55.033125+00:00")
    assert records[0].target_ctime == datetime("2021-10-16T15:26:20.406921+00:00")
