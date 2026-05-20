from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.linux.android._os import AndroidPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_android_os(target_android: Target) -> None:
    """Test if we detect Android and the version correctly."""
    target_android.add_plugin(AndroidPlugin)

    assert target_android.os == "android"
    assert target_android.version == "Android 4.4.2 (2013-10-31)"
    assert target_android.hostname == "TMG28071935"


@pytest.mark.parametrize(
    ("build_prop_locations"),
    [
        ([("/build.prop", "build.prop")]),
        ([("/system/build.prop", "build.prop")]),
        ([("/build.prop", "build.prop"), ("/foo/build.prop", "another.prop")]),
    ],
)
def test_android_os_detect_props(target_bare: Target, build_prop_locations: list[tuple[str, str]]) -> None:
    """Test if we detect different build.prop locations correctly."""
    fs = VirtualFilesystem()
    fs.makedirs("/data")
    fs.makedirs("/system")
    fs.makedirs("/vendor")
    fs.makedirs("/product")

    for prop, prop_file in build_prop_locations:
        fs.map_file(prop, absolute_path(f"_data/plugins/os/unix/linux/android/{prop_file}"))

    # prop file that should not be found
    fs.map_file_fh("/foo/bar/too/deep/build.prop", BytesIO(b"ro.not.found='true'"))

    target_bare._os_plugin = AndroidPlugin
    target_bare.filesystems.add(fs)
    target_bare.apply()

    target_bare.add_plugin(AndroidPlugin)

    assert target_bare.os == "android"
    assert sorted(map(str, target_bare._os.build_prop_paths)) == sorted(p for p, _ in build_prop_locations)
    assert target_bare._os.props
    assert target_bare.hostname == "TMG28071935"

    # test if mutual exclusive properties from different build.prop files are added to the dict.
    if "/foo/build.prop" in target_bare._os.build_prop_paths:
        assert target_bare._os.props.get("ro.foo") == "bar"

    # test if glob does not go too deep.
    assert "/foo/bar/too/deep/build.prop" not in target_bare._os.build_prop_paths


def test_android_os_users(target_android: Target, fs_android: VirtualFilesystem) -> None:
    """Test if we detect and parse Android users correctly."""
    fs_android.map_file("/data/system/users/userlist.xml", absolute_path("_data/plugins/os/unix/linux/android/users/userlist.xml"))
    fs_android.map_file("/data/system/users/0/settings_global.xml", absolute_path("_data/plugins/os/unix/linux/android/users/settings_global.xml"))
    fs_android.map_file("/data/system/users/0.xml", absolute_path("_data/plugins/os/unix/linux/android/users/0.xml"))
    target_android.add_plugin(AndroidPlugin)

    records = list(target_android.users())
    assert len(records) == 1
    assert records[0].hostname == "Pixel 7a"
    assert records[0].name == "Liz"
    assert records[0].uid == 0
    assert records[0].home == "/data/media/0"
    assert records[0].source == "/data/system/users/0.xml"
    assert records[0].usertype == "android.os.usertype.full.SYSTEM"
    assert records[0].last_login == datetime(2024, 7, 28, 3, 30, 36, 703000, tzinfo=timezone.utc)
    assert records[0].last_foreground == datetime(2024, 7, 28, 3, 30, 26, 264000, tzinfo=timezone.utc)
    assert records[0].flags == 19475
