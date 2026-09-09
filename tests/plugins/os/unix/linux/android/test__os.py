from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.linux.android._os import AndroidPlugin
from dissect.target.plugins.os.unix.linux.android.property import PropertyPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_android_os(target_android: Target) -> None:
    """Test generic AndroidPlugin OS properties."""
    target_android.add_plugin(AndroidPlugin)
    target_android.add_plugin(PropertyPlugin)

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
