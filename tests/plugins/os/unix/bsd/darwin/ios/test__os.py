from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugin import OperatingSystem
from dissect.target.plugins.os.unix.bsd.darwin.ios._os import IOSPlugin
from dissect.target.plugins.os.unix.bsd.darwin.ios.applications import (
    IOSApplicationsPlugin,
)
from dissect.target.plugins.os.unix.bsd.darwin.ios.locale import LocalePlugin
from dissect.target.target import Target
from tests._utils import absolute_path


def test_ios_detect(target_bare: Target, fs_ios: VirtualFilesystem) -> None:
    """Test if we correctly detect an iOS target."""
    target_bare.filesystems.add(fs_ios)
    target_bare.apply()
    assert IOSPlugin.detect(target_bare)
    assert target_bare._os_plugin is IOSPlugin


def test_ios_os(target_ios: Target, fs_ios: VirtualFilesystem) -> None:
    """Test if the iOS plugin works on an iOS target.

    Data based on example iOS image from Digital Corpora.

    Resources:
        - https://corp.digitalcorpora.org/corpora/mobile/iOS17/
    """

    fs_ios.map_dir("/", absolute_path("_data/plugins/os/unix/bsd/darwin/ios/_os"))
    target_ios.add_plugin(IOSPlugin)
    target_ios.add_plugin(LocalePlugin)
    target_ios.add_plugin(IOSApplicationsPlugin)
    target_ios.apply()

    assert target_ios.os == OperatingSystem.IOS
    assert target_ios.version == "iPhone OS 17.3 (21D50)"
    assert target_ios.architecture == "arm64-ios"
    assert target_ios.hostname == "This-Iss-iPhone"
    assert target_ios.timezone == "America/New_York"
    assert target_ios.language == ["en_US"]

    users = list(target_ios.users())
    assert len(users) == 43

    apps = list(target_ios.applications())
    assert len(apps) == 4

    assert sorted([app.name for app in apps]) == [
        # System apps
        "Books",
        "Calculator",
        "Compass",
        # AppStore apps
        "DuckDuckGo Private Browser",
    ]
