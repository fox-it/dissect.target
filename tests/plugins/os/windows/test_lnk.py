from flow.record.fieldtypes import datetime

from dissect.target.plugins.os.windows.lnk import LnkPlugin, LnkRecord
from tests._utils import absolute_path


def test_lnk(target_win, fs_win):
    lnk_file = absolute_path("_data/plugins/os/windows/lnk/pestudio.lnk")
    fs_win.map_file("Users/pestudio.lnk", lnk_file)

    target_win.add_plugin(LnkPlugin)

    records = list(target_win.lnk(None))

    assert len(records) == 1

    record = records[0]

    assert isinstance(record, type(LnkRecord()))
    assert str(record.lnk_path) == "sysvol\\users\\pestudio.lnk"
    assert record.lnk_name is None
    assert str(record.lnk_relativepath) == "pestudio.exe"
    assert str(record.lnk_workdir) == "C:\\Program Files\\pestudio"
    assert record.lnk_arguments is None
    assert record.lnk_iconlocation is None
    assert record.local_base_path == "C:\\Program Files\\pestudio\\pestudio.exe"
    assert record.common_path_suffix == ""
    assert record.lnk_net_name is None
    assert record.lnk_device_name is None
    assert str(record.lnk_full_path) == "C:\\Program Files\\pestudio\\pestudio.exe"
    assert record.machine_id == "desktop-i2purd1"
    assert record.target_mtime == datetime("2021-10-09T07:24:42+00:00")
    assert record.target_atime == datetime("2021-10-16T15:26:55.033125+00:00")
    assert record.target_ctime == datetime("2021-10-16T15:26:20.406921+00:00")
