from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.linux.android._os import AndroidPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_android_os(target_android: Target) -> None:
    """Test generic AndroidPlugin OS properties."""
    target_android.add_plugin(AndroidPlugin)

    # Detection
    assert target_android.os == "android"

    # Parsing of build.prop
    assert target_android.version == "Android 14 UQ1A.240105.004 (2024-01-05)"
    assert target_android.hostname == "TMG28071935"
    assert target_android.device == "Google LYNX Pixel 7a (lynx)"

    # Parsing of persistent_properties protobuf file
    assert target_android.timezone == "America/New_York"
    assert target_android.language == ["en_US"]

    # Parsing of ELF
    assert target_android.architecture == "aarch64-linux-android"


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

    assert target_bare.os == "android"
    assert sorted(map(str, target_bare._os.build_prop_paths)) == sorted(p for p, _ in build_prop_locations)
    assert target_bare._os.props
    assert target_bare.hostname == "TMG28071935"

    # test if mutual exclusive properties from different build.prop files are added to the dict.
    if "/foo/build.prop" in target_bare._os.build_prop_paths:
        assert target_bare._os.props.get("ro.foo") == "bar"

    # test if glob does not go too deep.
    assert "/foo/bar/too/deep/build.prop" not in target_bare._os.build_prop_paths
