import os

import pytest

from dissect.target.helpers import fsutil


def test_stat_result():
    with pytest.raises(TypeError):
        fsutil.stat_result([0])

    with pytest.raises(TypeError):
        fsutil.stat_result(list(range(100)))

    # ["st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size", "_st_atime", "_st_mtime", "_st_ctime"]
    values = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

    st = fsutil.stat_result(values)
    assert st[0] == st.st_mode == 0
    assert st[9] == 9
    assert st.st_ctime == 9.0
    assert st.st_ctime_ns == 9000000000
    assert st.st_blksize is None
    assert list(st) == [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

    # [..., "st_atime", "st_mtime", "st_ctime", "st_atime_ns", "st_mtime_ns", "st_ctime_ns"]
    values += [10, 11, 12, 13, 14, 15]

    st = fsutil.stat_result(values)
    assert st[0] == st.st_mode == 0
    assert st[9] == 9
    assert st.st_ctime == 12.0
    assert st.st_ctime_ns == 15
    assert st.st_blksize is None
    assert list(st) == [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

    my_stat = os.stat(__file__)
    st = fsutil.stat_result.copy(my_stat)
    assert st == my_stat
