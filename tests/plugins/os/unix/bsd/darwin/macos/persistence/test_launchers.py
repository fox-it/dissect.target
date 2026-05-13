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
                "com.apple.ecosystemagent.plist",
                "com.openssh.ssh-agent.plist",
            ),
            (
                "/System/Library/LaunchAgents/com.apple.ecosystemagent.plist",
                "/Users/user/Library/LaunchAgents/com.openssh.ssh-agent.plist",
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
    stat_results = []
    entries = []

    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/persistence/launchers/{name}")
        fs_unix.map_file(path, data_file)
        entry = fs_unix.get(path)
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199
        stat_results.append(stat_result)
        entries.append(entry)

    with (
        patch.object(entries[0], "stat", return_value=stat_results[0]),
    ):
        target_unix.add_plugin(LaunchersPlugin)

        results = list(target_unix.launch_agents())

        results.sort(key=lambda r: (r.source, getattr(r, "plist_path", "") or ""))

        assert len(results) == 6

        assert results[0].label == "com.apple.ecosystemagent"
        assert results[0].program is None
        assert results[0].program_arguments == [
            "/System/Library/PrivateFrameworks/Ecosystem.framework/Support/ecosystemagent"
        ]
        assert results[0].keep_alive is None
        assert results[0].run_at_load is None
        assert results[0].process_type == "Background"
        assert results[0].limit_load_to_session_type is None
        assert results[0].limit_load_from_hardware == []
        assert results[0].launch_events == []
        assert results[0].mach_services == [
            "('com.apple.ecosystem.agent.clear-notifications', True)",
            "('com.apple.ecosystem.agent.notifications', True)",
            "('com.apple.ecosystem.unsupportedapplicationlist', True)",
            "('com.apple.usernotifications.delegate.com.apple.ecosystem.notifications', True)",
        ]
        assert results[0].enable_pressured_exit == "True"
        assert results[0].enable_transactions
        assert results[0].environment_variables == []
        assert results[0].user_name is None
        assert results[0].low_priority_io
        assert results[0].watch_paths == []
        assert results[0].queue_directories == []
        assert results[0].plist_path is None
        assert results[0].source == "/System/Library/LaunchAgents/com.apple.ecosystemagent.plist"

        assert results[1].un_setting_alerts is None
        assert results[1].un_setting_always_show_previews is None
        assert results[1].un_setting_lock_screen is None
        assert results[1].un_setting_modal_alert_style is None
        assert results[1].un_automatically_show_settings
        assert results[1].un_setting_notification_center is None
        assert results[1].un_daemon_should_receive_background_responses
        assert results[1].un_suppress_user_authorization_prompt
        assert results[1].plist_path == "UNUserNotificationCenter"
        assert results[1].source == "/System/Library/LaunchAgents/com.apple.ecosystemagent.plist"

        assert results[2].un_setting_alerts
        assert not results[2].un_setting_always_show_previews
        assert results[2].un_setting_lock_screen
        assert results[2].un_setting_modal_alert_style
        assert results[2].un_automatically_show_settings is None
        assert results[2].un_setting_notification_center
        assert results[2].un_daemon_should_receive_background_responses is None
        assert results[2].un_suppress_user_authorization_prompt is None
        assert results[2].plist_path == "UNUserNotificationCenter/UNDefaultSettings"
        assert results[2].source == "/System/Library/LaunchAgents/com.apple.ecosystemagent.plist"

        assert results[3].un_notification_icon_default == "notification-settings"
        assert results[3].un_notification_icon_settings == "notification-settings"

        assert results[3].plist_path == "UNUserNotificationCenter/UNNotificationIcons"
        assert results[3].source == "/System/Library/LaunchAgents/com.apple.ecosystemagent.plist"

        assert results[4].label == "com.openssh.ssh-agent"
        assert results[4].program is None
        assert results[4].program_arguments == ["/usr/bin/ssh-agent", "-l"]
        assert results[4].process_type is None
        assert results[4].mach_services == []
        assert results[4].enable_pressured_exit is None
        assert results[4].enable_transactions
        assert results[4].environment_variables == []
        assert results[4].user_name is None
        assert results[4].watch_paths == []
        assert results[4].queue_directories == []
        assert results[4].plist_path is None
        assert results[4].source == "/Users/user/Library/LaunchAgents/com.openssh.ssh-agent.plist"

        assert results[5].socket_key is None
        assert results[5].sock_type is None
        assert results[5].sock_passive is None
        assert results[5].sock_node_name is None
        assert results[5].sock_service_name is None
        assert results[5].sock_family is None
        assert results[5].sock_protocol is None
        assert results[5].sock_path_mode is None
        assert results[5].sock_path_name is None
        assert results[5].secure_socket_with_key == "SSH_AUTH_SOCK"
        assert results[5].sock_path_owner is None
        assert results[5].sock_path_group is None
        assert results[5].bonjour is None
        assert results[5].multicast_group is None
        assert results[5].receive_packet_info is None
        assert results[5].plist_path == "Sockets/Listeners"
        assert results[5].source == "/Users/user/Library/LaunchAgents/com.openssh.ssh-agent.plist"


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            ("org.cups.cupsd.plist",),
            ("/System/Library/LaunchDaemons/org.cups.cupsd.plist",),
        ),
    ],
)
def test_launch_daemons(
    names: tuple[str, ...],
    paths: tuple[str, ...],
    target_unix: Target,
    fs_unix: VirtualFilesystem,
) -> None:
    stat_results = []

    entries = []

    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/persistence/launchers/{name}")
        fs_unix.map_file(path, data_file)
        entry = fs_unix.get(path)
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199
        stat_results.append(stat_result)
        entries.append(entry)

    with (
        patch.object(entries[0], "stat", return_value=stat_results[0]),
    ):
        target_unix.add_plugin(LaunchersPlugin)

        results = list(target_unix.launch_daemons())
        results.sort(key=lambda r: (r.source, getattr(r, "plist_path", "") or ""))

        assert len(results) == 2

        assert results[0].label == "org.cups.cupsd"
        assert results[0].program is None
        assert results[0].program_arguments == ["/usr/sbin/cupsd", "-l"]
        assert results[0].keep_alive == "[('PathState', {'/private/var/spool/cups/cache/org.cups.cupsd': True})]"
        assert results[0].on_demand is None
        assert results[0].disabled is None
        assert results[0].run_at_load is None
        assert results[0].launch_only_once is None
        assert results[0].process_type == "Interactive"
        assert results[0].wait is None
        assert results[0].limit_load_to_session_type is None
        assert results[0].limit_load_to_developer_mode is None
        assert results[0].limit_load_from_variant is None
        assert results[0].limit_load_to_variant is None
        assert results[0].limit_load_from_boot_mode is None
        assert results[0].limit_load_to_boot_mode == []
        assert results[0].limit_load_from_hardware == []
        assert results[0].limit_load_to_hardware == []
        assert results[0].launch_events == []
        assert results[0].mach_services == []
        assert results[0].enable_pressured_exit is None
        assert results[0].enable_transactions
        assert results[0].environment_variables == [
            "('CUPS_DEBUG_LOG', '/var/log/cups/debug_log')",
            "('CUPS_DEBUG_LEVEL', '3')",
            "('CUPS_DEBUG_FILTER', '^(cupsDo|cupsGet|cupsMake|cupsSet|http|_http|ipp|_ipp|mime).*')",
        ]
        assert results[0].user_name is None
        assert results[0].init_groups is None
        assert results[0].group_name is None
        assert results[0].start_interval is None
        assert results[0].start_calendar_interval == []
        assert results[0].throttle_interval is None
        assert results[0].enable_globbing is None
        assert results[0].standard_in_path is None
        assert results[0].standard_out_path is None
        assert results[0].standard_error_path is None
        assert results[0].nice is None
        assert results[0].abandon_process_group is None
        assert results[0].low_priority_io is None
        assert results[0].root_directory is None
        assert results[0].working_directory is None
        assert results[0].umask is None
        assert results[0].time_out is None
        assert results[0].exit_time_out == 60
        assert results[0].watch_paths == []
        assert results[0].queue_directories == []
        assert results[0].start_on_mount is None
        assert results[0].soft_resource_limits == []

        assert results[1].hostname == "localhost"
        assert results[1].domain is None
        assert results[1].listeners == ["{'SockPathMode': 49663, 'SockPathName': '/private/var/run/cupsd'}"]
        assert results[1].plist_path == "Sockets"
        assert results[1].source == "/System/Library/LaunchDaemons/org.cups.cupsd.plist"
