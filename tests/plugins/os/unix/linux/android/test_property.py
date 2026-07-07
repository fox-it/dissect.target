from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.linux.android._os import AndroidPlugin
from dissect.target.plugins.os.unix.linux.android.property import PropertyPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.target import Target


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
        fs.map_file(prop, absolute_path(f"_data/plugins/os/unix/linux/android/system/{prop_file}"))

    # prop file that should not be found
    fs.map_file_fh("/foo/bar/too/deep/build.prop", BytesIO(b"ro.not.found='true'"))

    target_bare._os_plugin = AndroidPlugin
    target_bare.filesystems.add(fs)
    target_bare.apply()

    target_bare.add_plugin(AndroidPlugin)
    target_bare.add_plugin(PropertyPlugin)

    assert target_bare.os == "android"
    assert sorted(map(str, target_bare.property.build_prop_paths)) == sorted(p for p, _ in build_prop_locations)
    assert target_bare.property.props
    assert target_bare.hostname == "TMG28071935"

    # test if mutual exclusive properties from different build.prop files are added to the dict.
    if "/foo/build.prop" in target_bare.property.build_prop_paths:
        assert target_bare.property.get("ro.foo") == "bar"

    # test if glob does not go too deep.
    assert "/foo/bar/too/deep/build.prop" not in target_bare.property.build_prop_paths
