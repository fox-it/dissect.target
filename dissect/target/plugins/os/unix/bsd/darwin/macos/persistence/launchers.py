from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_plist_records
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.general import _build_userdirs

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

re_illegal_characters = re.compile(r"[\(\): \.\-#\/\>\<]")

LauncherRecord = [
    ("string", "label"),
    ("string", "program"),
    ("string[]", "program_arguments"),
    ("string", "keep_alive"),
    ("boolean", "on_demand"),
    ("string", "disabled"),
    ("boolean", "run_at_load"),
    ("boolean", "launch_only_once"),
    ("string", "process_type"),
    ("boolean", "wait"),
    ("string", "limit_load_to_session_type"),
    ("boolean", "limit_load_to_developer_mode"),
    ("string", "limit_load_from_variant"),
    ("string", "limit_load_to_variant"),
    ("string", "limit_load_from_boot_mode"),
    ("string[]", "limit_load_to_boot_mode"),
    ("string[]", "limit_load_from_hardware"),
    ("string[]", "limit_load_to_hardware"),
    ("string[]", "launch_events"),
    ("string[]", "mach_services"),
    ("string", "enable_pressured_exit"),
    ("boolean", "enable_transactions"),
    ("string[]", "environment_variables"),
    ("string", "user_name"),
    ("boolean", "init_groups"),
    ("string", "group_name"),
    ("varint", "start_interval"),
    ("string[]", "start_calendar_interval"),
    ("varint", "throttle_interval"),
    ("boolean", "enable_globbing"),
    ("string", "standard_in_path"),
    ("string", "standard_out_path"),
    ("string", "standard_error_path"),
    ("varint", "nice"),
    ("boolean", "abandon_process_group"),
    ("boolean", "low_priority_io"),
    ("string", "root_directory"),
    ("string", "working_directory"),
    ("varint", "umask"),
    ("varint", "time_out"),
    ("varint", "exit_time_out"),
    ("string[]", "watch_paths"),
    ("string[]", "queue_directories"),
    ("boolean", "start_on_mount"),
    ("string[]", "soft_resource_limits"),
    ("string[]", "hard_resource_limits"),
    ("boolean", "debug"),
    ("boolean", "wait_for_debugger"),
    ("string", "plist_path"),
    ("path", "source"),
]

SocketRecord = [
    ("string", "socket_key"),
    ("string", "sock_type"),
    ("boolean", "sock_passive"),
    ("string", "sock_node_name"),
    ("string", "sock_service_name"),
    ("string", "sock_family"),
    ("string", "sock_protocol"),
    ("varint", "sock_path_mode"),
    ("string", "sock_path_name"),
    ("string", "secure_socket_with_key"),
    ("varint", "sock_path_owner"),
    ("varint", "sock_path_group"),
    ("string", "bonjour"),
    ("string", "multicast_group"),
    ("boolean", "receive_packet_info"),
    ("string", "plist_path"),
    ("path", "source"),
]

UNRecord = [
    ("boolean", "un_setting_alerts"),
    ("boolean", "un_setting_always_show_previews"),
    ("boolean", "un_setting_lock_screen"),
    ("boolean", "un_setting_modal_alert_style"),
    ("boolean", "un_automatically_show_settings"),
    ("boolean", "un_setting_notification_center"),
    ("boolean", "un_daemon_should_receive_background_responses"),
    ("boolean", "un_suppress_user_authorization_prompt"),
    ("string", "plist_path"),
    ("path", "source"),
]

UNNotificationRecord = [
    ("string", "un_notification_icon_default"),
    ("string", "un_notification_icon_settings"),
    ("string", "plist_path"),
    ("path", "source"),
]

ListenersRecord = [
    ("string[]", "listeners"),
    ("string", "plist_path"),
    ("path", "source"),
]

FIELD_MAPPINGS = {
    # LauncherRecord
    "Label": "label",
    "Program": "program",
    "ProgramArguments": "program_arguments",
    "KeepAlive": "keep_alive",
    "OnDemand": "on_demand",
    "Disabled": "disabled",
    "RunAtLoad": "run_at_load",
    "LaunchOnlyOnce": "launch_only_once",
    "ProcessType": "process_type",
    "Wait": "wait",
    "LimitLoadToSessionType": "limit_load_to_session_type",
    "LimitLoadFromHardware": "limit_load_from_hardware",
    "LimitLoadToDeveloperMode": "limit_load_to_developer_mode",
    "LimitLoadFromVariant": "limit_load_from_variant",
    "LimitLoadToVariant": "limit_load_to_variant",
    "LimitLoadFromBootMode": "limit_load_from_boot_mode",
    "LimitLoadToBootMode": "limit_load_to_boot_mode",
    "LimitLoadToHardware": "limit_load_to_hardware",
    "LaunchEvents": "launch_events",
    "MachServices": "mach_services",
    "EnablePressuredExit": "enable_pressured_exit",
    "EnableTransactions": "enable_transactions",
    "EnvironmentVariables": "environment_variables",
    "UserName": "user_name",
    "GroupName": "group_name",
    "StartInterval": "start_interval",
    "StartCalendarInterval": "start_calendar_interval",
    "ThrottleInterval": "throttle_interval",
    "EnableGlobbing": "enable_globbing",
    "StandardInPath": "standard_in_path",
    "StandardOutPath": "standard_out_path",
    "StandardErrorPath": "standard_error_path",
    "Nice": "nice",
    "LowPriorityIO": "low_priority_io",
    "AbandonProcessGroup": "abandon_process_group",
    "RootDirectory": "root_directory",
    "WorkingDirectory": "working_directory",
    "Umask": "umask",
    "TimeOut": "time_out",
    "ExitTimeOut": "exit_time_out",
    "InitGroups": "init_groups",
    "WatchPaths": "watch_paths",
    "QueueDirectories": "queue_directories",
    "StartOnMount": "start_on_mount",
    "SoftResourceLimits": "soft_resource_limits",
    "HardResourceLimits": "hard_resource_limits",
    "Debug": "debug",
    "WaitForDebugger": "wait_for_debugger",
    # SocketRecord
    "SocketKey": "socket_key",
    "SockType": "sock_type",
    "SockPassive": "sock_passive",
    "SockNodeName": "sock_node_name",
    "SockServiceName": "sock_service_name",
    "SockFamily": "sock_family",
    "SockProtocol": "sock_protocol",
    "SockPathMode": "sock_path_mode",
    "SockPathName": "sock_path_name",
    "SecureSocketWithKey": "secure_socket_with_key",
    "SockPathOwner": "sock_path_owner",
    "SockPathGroup": "sock_path_group",
    "Bonjour": "bonjour",
    "MulticastGroup": "multicast_group",
    "ReceivePacketInfo": "receive_packet_info",
    # UNRecord
    "UNSettingAlerts": "un_setting_alerts",
    "UNSettingAlwaysShowPreviews": "un_setting_always_show_previews",
    "UNSettingLockScreen": "un_setting_lock_screen",
    "UNSettingModalAlertStyle": "un_setting_modal_alert_style",
    "UNAutomaticallyShowSettings": "un_automatically_show_settings",
    "UNSettingNotificationCenter": "un_setting_notification_center",
    "UNDaemonShouldReceiveBackgroundResponses": "un_daemon_should_receive_background_responses",
    "UNSuppressUserAuthorizationPrompt": "un_suppress_user_authorization_prompt",
    # UNNotificationRecord
    "UNNotificationIconDefault": "un_notification_icon_default",
    "UNNotificationIconSettings": "un_notification_icon_settings",
    # ListenersRecord
    "Listeners": "listeners",
}

LaunchAgentRecords = (
    TargetRecordDescriptor(
        "macos/launch_agents",
        LauncherRecord,
    ),
    TargetRecordDescriptor(
        "macos/launch_agents/socket",
        SocketRecord,
    ),
    TargetRecordDescriptor(
        "macos/launch_agents/un",
        UNRecord,
    ),
    TargetRecordDescriptor(
        "macos/launch_agents/un_notification",
        UNNotificationRecord,
    ),
)

LaunchDaemonRecords = (
    TargetRecordDescriptor(
        "macos/launch_daemons",
        LauncherRecord,
    ),
    TargetRecordDescriptor(
        "macos/launch_daemons/socket",
        SocketRecord,
    ),
    TargetRecordDescriptor(
        "macos/launch_daemons/listeners",
        ListenersRecord,
    ),
)

COLLAPSE_PATHS = {
    ("LaunchEvents", False),
    ("MachServices", True),
    ("EnvironmentVariables", True),
    ("KeepAlive", False),
    ("SoftResourceLimits", True),
    ("HardResourceLimits", True),
    ("MultipleInstances", True),
    ("UserName", True),
    ("GroupName", True),
    ("RemoteServices", False),
    ("JetsamProperties", True),
    ("LimitLoadToSessionType", True),
    ("Version4", False),
    ("EnablePressuredExit", True),
    ("LimitLoadToHardware", True),
    ("_PanicOnCrash", True),
    ("LimitLoadFromHardware", True),
    ("StartCalendarInterval", True),
    ("PublishesEvents", False),
    ("_AdditionalProperties", False),
    ("Disabled", True),
    ("com.apple.usbcd", True),
    ("NoEnvironmentVariables", True),
    ("NO_EnvironmentVariables", True),
    ("NSAppTransportSecurity", True),
    ("_UrgentLogSubmission", True),
    ("AppIntents", True),
}


class LaunchersPlugin(Plugin):
    """macOS launchers plugin."""

    SYSTEM_LAUNCH_AGENT_PATHS = (
        "/System/Library/LaunchAgents/*.plist",
        "/Library/LaunchAgents/*.plist",
    )

    SYSTEM_LAUNCH_DAEMON_PATHS = (
        "/System/Library/LaunchDaemons/*.plist",
        "/Library/LaunchDaemons/*.plist",
    )

    USER_LAUNCH_AGENT_PATHS = ("Library/LaunchAgents/*.plist",)

    USER_LAUNCH_DAEMON_PATHS = ("Library/LaunchDaemons/*.plist",)

    def __init__(self, target: Target):
        super().__init__(target)

        self.launch_agent_files = set()
        self.launch_daemon_files = set()
        self._find_files()

    def check_compatible(self) -> None:
        if not (self.launch_agent_files or self.launch_daemon_files):
            raise UnsupportedPluginError("No Agent or Deamon files found")

    def _find_files(self) -> None:
        # --- System-wide LaunchAgents ---
        for pattern in self.SYSTEM_LAUNCH_AGENT_PATHS:
            for path in self.target.fs.glob(pattern):
                self.launch_agent_files.add(path)

        # --- Per-user LaunchAgents ---
        for _, path in _build_userdirs(self, self.USER_LAUNCH_AGENT_PATHS):
            self.launch_agent_files.add(path)

        # --- System-wide LaunchDaemons ---
        for pattern in self.SYSTEM_LAUNCH_DAEMON_PATHS:
            for path in self.target.fs.glob(pattern):
                self.launch_daemon_files.add(path)

        # --- Per-user LaunchDaemons ---
        for _, path in _build_userdirs(self, self.USER_LAUNCH_DAEMON_PATHS):
            self.launch_daemon_files.add(path)

    @export(record=LaunchAgentRecords)
    def launch_agents(self) -> Iterator[LaunchAgentRecords]:
        """Yield macOS launch agent plist files."""
        yield from build_plist_records(
            self, self.launch_agent_files, LaunchAgentRecords, COLLAPSE_PATHS, FIELD_MAPPINGS
        )

    @export(record=LaunchDaemonRecords)
    def launch_daemons(self) -> Iterator[LaunchDaemonRecords]:
        """Yield macOS launch daemon plist files."""
        yield from build_plist_records(
            self, self.launch_daemon_files, LaunchDaemonRecords, COLLAPSE_PATHS, FIELD_MAPPINGS
        )
