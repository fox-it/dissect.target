from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.persistence.launchers import LaunchersPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            (
                "com.apple.seserviced.plist",
                "com.apple.AMPArtworkAgent.plist",
                "com.apple.familynotificationd.plist",
                "com.apple.sidecar-hid-relay.plist",
                "com.apple.WirelessRadioManager-osx.plist",
            ),
            (
                "/Users/user/Library/LaunchAgents/com.apple.seserviced.plist",
                "/System/Library/LaunchAgents/com.apple.AMPArtworkAgent.plist",
                "/System/Library/LaunchAgents/com.apple.familynotificationd.plist",
                "/Library/LaunchAgents/com.apple.sidecar-hid-relay.plist",
                "/System/Library/LaunchDaemons/com.apple.WirelessRadioManager-osx.plist",
            ),
        ),
    ],
)
def test_launch_agents(
    names: tuple[str, ...],
    paths: tuple[str, ...],
    target_unix: Target,
    fs_unix: VirtualFilesystem,
) -> None:
    user = UnixUserRecord(
        name="user",
        uid=501,
        gid=20,
        home="/Users/user",
        shell="/bin/zsh",
    )
    target_unix.users = lambda: [user]

    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/persistence/launchers/{name}")
        fs_unix.map_file(path, data_file)
        entry = fs_unix.get(path)
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(LaunchersPlugin)

        results = list(target_unix.launch_agents())
        results.sort(key=lambda r: r.source)

        assert len(results) == 4

        assert results[0].EnablePressuredExit
        assert results[0].EnableTransactions
        assert results[0].Label == "com.apple.sidecar-display-agent"
        assert results[0].ProcessType == "Interactive"
        assert results[0].Program == "/usr/libexec/SidecarDisplayAgent"
        assert results[0].com_apple_sidecar_display_agent
        assert results[0].source == "/Library/LaunchAgents/com.apple.sidecar-hid-relay.plist"

        assert results[1].EnablePressuredExit
        assert results[1].EnableTransactions
        assert results[1].Label == "com.apple.AMPArtworkAgent"
        assert results[1].ProcessType == "Adaptive"
        assert results[1].ProgramArguments == (
            "['/System/Library/PrivateFrameworks/AMPLibrary.framework/Versions/A/Support/AMPArtworkAgent', '--launchd']"
        )
        assert results[1].com_apple_amp_artworkd
        assert results[1].source == "/System/Library/LaunchAgents/com.apple.AMPArtworkAgent.plist"

        assert results[2].EnableTransactions
        assert results[2].Label == "com.apple.familynotificationd"
        assert results[2].Program == (
            "/System/Library/PrivateFrameworks/FamilyNotification.framework/familynotificationd"
        )
        assert results[2].LimitLoadToSessionType == "['LoginWindow', 'Aqua']"
        assert results[2].bundleid == "com.apple.familyalert"
        assert results[2].POSIXSpawnType == "Adaptive"
        assert results[2].ExitTimeOut == 1
        assert results[2].delay_registration
        assert results[2].com_apple_familynotification_agent
        assert results[2].com_apple_usernotifications_delegate_com_apple_familynotifications
        assert results[2].events == (
            "['didDismissAlert', 'didActivateNotification', 'didDeliverNotification', "
            "'didSnoozeAlert', 'didRemoveDeliveredNotifications', "
            "'didExpireNotifications']"
        )
        assert results[2].source == "/System/Library/LaunchAgents/com.apple.familynotificationd.plist"

        assert results[3].EnablePressuredExit
        assert results[3].EnableTransactions
        assert results[3].Label == "com.apple.seserviced"
        assert results[3].ProcessType == "Adaptive"
        assert results[3].Program == "/usr/libexec/seserviced"
        assert results[3].Repeating
        assert results[3].LimitLoadFromVariant == "HasFactoryContent"
        assert results[3].com_apple_seserviced
        assert results[3].com_apple_seserviced_sereservation_client
        assert results[3].source == "/Users/user/Library/LaunchAgents/com.apple.seserviced.plist"


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            (
                "com.apple.WirelessRadioManager-osx.plist",
                "com.apple.cfprefsd.xpc.daemon.plist",
                "com.apple.perfpowermetricd.plist",
                "com.apple.sidecar-hid-relay.plist",
            ),
            (
                "/System/Library/LaunchDaemons/com.apple.WirelessRadioManager-osx.plist",
                "/Users/user/Library/LaunchDaemons/com.apple.cfprefsd.xpc.daemon.plist",
                "/Library/LaunchDaemons/com.apple.perfpowermetricd.plist",
                "/Library/LaunchAgents/com.apple.sidecar-hid-relay.plist",
            ),
        ),
    ],
)
def test_launch_daemons(
    names: tuple[str, ...],
    paths: tuple[str, ...],
    target_unix: Target,
    fs_unix: VirtualFilesystem,
) -> None:
    user = UnixUserRecord(
        name="user",
        uid=501,
        gid=20,
        home="/Users/user",
        shell="/bin/zsh",
    )
    target_unix.users = lambda: [user]
    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/persistence/launchers/{name}")
        fs_unix.map_file(path, data_file)
        entry = fs_unix.get(path)
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(LaunchersPlugin)

        results = list(target_unix.launch_daemons())
        results.sort(key=lambda r: r.source)

        assert len(results) == 3

        assert results[0].EnablePressuredExit
        assert results[0].EnableTransactions
        assert results[0].Label == "com.apple.perfpowermetricd"
        assert results[0].ProcessType == "Interactive"
        assert results[0].com_apple_PerfPowerMetricMonitor_xpc
        assert results[0].ProgramArguments == "['/usr/libexec/perfpowermetricd']"
        assert results[0].source == "/Library/LaunchDaemons/com.apple.perfpowermetricd.plist"

        assert results[1].EnablePressuredExit
        assert results[1].Label == "com.apple.WirelessRadioManager"
        assert results[1].POSIXSpawnType == "Interactive"
        assert results[1].ThrottleInterval == 10
        assert results[1].com_apple_WirelessCoexManager
        assert results[1].com_apple_WirelessRadioManager
        assert results[1].ProgramArguments == "['/usr/sbin/WirelessRadioManagerd']"
        assert results[1].source == "/System/Library/LaunchDaemons/com.apple.WirelessRadioManager-osx.plist"

        assert not results[2].EnablePressuredExit
        assert results[2].EnableTransactions
        assert results[2].Label == "com.apple.cfprefsd.xpc.daemon"
        assert results[2].POSIXSpawnType == "Adaptive"
        assert results[2].NumberOfFiles == 512
        assert results[2].com_apple_cfprefsd_daemon
        assert results[2].ProgramArguments == "['/usr/sbin/cfprefsd', 'daemon']"
        assert results[2].source == "/Users/user/Library/LaunchDaemons/com.apple.cfprefsd.xpc.daemon.plist"
