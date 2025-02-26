import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.linux.android._os import AndroidPlugin
from tests._utils import absolute_path


def test_android_os(target_android: Target) -> None:
    target_android.add_plugin(AndroidPlugin)

    assert target_android.os == "android"
    assert target_android.version == "Android 4.4.2 (2013-10-31)"
    assert target_android.hostname == "TMG28071935"


normal_prop = absolute_path("_data/plugins/os/unix/linux/android/build.prop")
another_prop = absolute_path("_data/plugins/os/unix/linux/android/another.prop")


@pytest.mark.parametrize(
    "build_prop_locations",
    [
        ([("/build.prop", normal_prop)]),
        ([("/system/build.prop", normal_prop)]),
        ([("/build.prop", normal_prop), ("/foo/build.prop", another_prop)]),
    ],
)
def test_android_os_detect_props(target_bare: Target, build_prop_locations: list[tuple[str, str]]) -> None:
    """test if we detect different build.prop locations correctly."""

    fs = VirtualFilesystem()
    for prop, prop_file in build_prop_locations:
        fs.map_file(prop, prop_file)

    target_bare._os_plugin = AndroidPlugin
    target_bare.filesystems.add(fs)
    target_bare.apply()

    target_bare.add_plugin(AndroidPlugin)

    assert target_bare.os == "android"
    assert sorted(list(map(str, target_bare._os.build_prop_paths))) == sorted([p for p, _ in build_prop_locations])
    assert target_bare._os.props
    assert target_bare.hostname == "TMG28071935"

    # test if mutual exclusive properties from different build.prop files are added to the dict.
    if "/foo/build.prop" in target_bare._os.build_prop_paths:
        assert target_bare._os.props.get("ro.foo") == "bar"
