from dissect.target import Target
from dissect.target.plugins.os.unix.linux.android._os import AndroidPlugin


def test_android_os(target_android: Target) -> None:
    target_android.add_plugin(AndroidPlugin)

    assert target_android.os == "android"
    assert target_android.version == "Android 4.4.2 (2013-10-31)"
    assert target_android.hostname == "TMG28071935"
