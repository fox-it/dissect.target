from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_paths import _build_userdirs
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_plist_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

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
    ("string[]", "path_state"),
    ("string[]", "other_job_enabled"),
    ("boolean", "low_priority_background_io"),
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
    "path_state": "PathState",
    "other_job_enabled": "OtherJobEnabled",
    "low_priority_background_io": "LowPriorityBackgroundIO",
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
    """macOS launchers plugin.

    Parses LaunchAgent and LaunchDaemon files, which are configuration-based background services
    managed by macOS that automatically run tasks or processes based on system or user-level triggers.

    References:
        - https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html
        - https://www.manpagez.com/man/5/launchd.plist/osx-10.13.1.php
        - https://developer.apple.com/documentation/usernotifications/unusernotificationcenter
        - https://medium.com/@durgaviswanadh/understanding-macos-launchagents-and-login-items-a-clear-practical-guide-5c0e39e3a6b3
    """

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

        self.launch_agent_files = self._find_agent_files()
        self.launch_daemon_files = self._find_daemon_files()

    def check_compatible(self) -> None:
        if not (self.launch_agent_files or self.launch_daemon_files):
            raise UnsupportedPluginError("No Agent or Deamon files found")

    def _find_agent_files(self) -> set:
        launch_agent_files = set()
        for pattern in self.SYSTEM_LAUNCH_AGENT_PATHS:
            for path in self.target.fs.glob(pattern):
                launch_agent_files.add(path)
        for _, path in _build_userdirs(self, self.USER_LAUNCH_AGENT_PATHS):
            launch_agent_files.add(path)
        return launch_agent_files

    def _find_daemon_files(self) -> set:
        launch_daemon_files = set()
        for pattern in self.SYSTEM_LAUNCH_DAEMON_PATHS:
            for path in self.target.fs.glob(pattern):
                launch_daemon_files.add(path)
        for _, path in _build_userdirs(self, self.USER_LAUNCH_DAEMON_PATHS):
            launch_daemon_files.add(path)
        return launch_daemon_files

    @export(record=LaunchAgentRecords)
    def launch_agents(self) -> Iterator[LaunchAgentRecords]:
        """Return macOS LaunchAgent plist entries.

        Yields the following record types extracted from
        LaunchAgent plist files:

        .. code-block:: text

            LauncherRecord:
                label (string): Required key that uniquely identifies the job in launchd.
                program (string): Absolute path to the executable mapped to execv(3).
                program_arguments (string[]): Argument vector passed to execvp(3).
                keep_alive (string): Controls whether the job remains running continuously
                    or is restarted based on configured conditions.
                on_demand (boolean): Deprecated key; false is equivalent to KeepAlive=true.
                disabled (string): Specifies if the job should be loaded by default; may be overridden externally.
                run_at_load (boolean): Starts the job when it is loaded into launchd.
                launch_only_once (boolean): Indicates the job must not be respawned after execution.
                process_type (string): Declares the job classification (e.g. Background,
                    Adaptive, Interactive) used for resource management.
                wait (boolean): inetd compatibility flag determining whether sockets are passed
                    directly or accepted on behalf of the job.
                limit_load_to_developer_mode (boolean): Restricts execution depending on developer mode state.
                limit_load_to_variant (string): Restricts loading to specific system variants.
                limit_load_from_variant (string): Prevents loading on specific system variants.
                limit_load_to_boot_mode (string[]): Restricts loading to specified boot modes.
                limit_load_from_boot_mode (string): Prevents loading when in specified boot mode.
                limit_load_to_hardware (string[]): Restricts loading to systems matching hardware values.
                limit_load_from_hardware (string[]): Prevents loading on matching hardware values.
                launch_events (string[]): Defines event-based triggers used to start the job.
                mach_services (string[]): Mach services registered in the bootstrap namespace.
                enable_pressured_exit (string): Enables lifecycle management under memory pressure.
                enable_transactions (boolean): Indicates the job uses XPC transaction tracking for safe termination.
                environment_variables (string[]): Environment variables to set before execution.
                user_name (string): User identity the job runs as (for system domain jobs).
                init_groups (boolean): Whether initgroups(3) is called to initialize group membership.
                group_name (string): Group identity the job runs as.
                start_interval (varint): Starts the job every specified number of seconds.
                start_calendar_interval (string[]): Scheduling rules similar to cron-style timing.
                throttle_interval (varint): Minimum interval between job invocations.
                enable_globbing (boolean): Expands program arguments using glob(3) before execution.
                standard_in_path (string): File mapped to stdin(4).
                standard_out_path (string): File mapped to stdout(4).
                standard_error_path (string): File mapped to stderr(4).
                nice (varint): Scheduling priority applied with nice(3).
                abandon_process_group (boolean): Prevents launchd from terminating the job's process group.
                low_priority_io (boolean): Marks the job as low priority for filesystem I/O.
                root_directory (string): Directory used as a chroot(2) environment.
                working_directory (string): Directory set via chdir(2) before execution.
                umask (varint): Value passed to umask(2) for file creation permissions.
                time_out (varint): Idle timeout hint (deprecated and not implemented).
                exit_time_out (varint): Time between SIGTERM and SIGKILL when stopping the job.
                watch_paths (string[]): Triggers job when specified filesystem paths change.
                queue_directories (string[]): Keeps job alive while directories are not empty.
                start_on_mount (boolean): Starts the job when filesystems are mounted.
                soft_resource_limits (string[]): Soft setrlimit(2)-based resource limits.
                hard_resource_limits (string[]): Hard setrlimit(2)-based resource limits.
                debug (boolean): Temporarily elevates logging to debug level for this job.
                wait_for_debugger (boolean): Launches the process suspended until a debugger attaches.

            SocketRecord:
                socket_key (string): Identifier used to associate socket configuration with the job.
                sock_type (string): Socket type passed to socket(2) (e.g. stream, dgram).
                sock_passive (boolean): Determines if listen(2) or connect(2) is used.
                sock_node_name (string): Node name used for bind(2) or connect(2).
                sock_service_name (string): Service name or port used for the socket.
                sock_family (string): Address family (e.g. IPv4, IPv6, Unix).
                sock_protocol (string): Protocol used by the socket (TCP or UDP).
                sock_path_mode (varint): File mode for Unix domain socket.
                sock_path_name (string): Filesystem path for Unix domain socket.
                secure_socket_with_key (string): Environment variable key assigned to a generated socket path.
                sock_path_owner (varint): User ID ownership of the socket file.
                sock_path_group (varint): Group ID of the socket file.
                bonjour (string): Registers the service with Bonjour if specified.
                multicast_group (string): Multicast group joined by the socket.

            UNRecord:
                un_setting_alerts (boolean): Indicates if notifications are allowed to show alerts.
                un_setting_always_show_previews (boolean): Controls whether notification previews are always displayed.
                un_setting_lock_screen (boolean): Determines if notifications are shown on the lock screen.
                un_setting_modal_alert_style (boolean): Indicates if notifications use modal alert presentation.
                un_automatically_show_settings (boolean): Indicates if notification settings are shown automatically.
                un_setting_notification_center (boolean): Indicates if notifications appear in Notification Center.
                un_daemon_should_receive_background_responses (boolean): Indicates background handling of
                    notification responses.
                un_suppress_user_authorization_prompt (boolean): Indicates suppression of notification
                    permission prompts.

            UNNotificationRecord:
                un_notification_icon_default (string): Default icon used for notifications.
                un_notification_icon_settings (string): Icon used in notification settings.
        """
        yield from build_plist_records(
            self, self.launch_agent_files, LaunchAgentRecords, COLLAPSE_PATHS, FIELD_MAPPINGS
        )

    @export(record=LaunchDaemonRecords)
    def launch_daemons(self) -> Iterator[LaunchDaemonRecords]:
        """Return macOS LaunchDaemon plist entries.

        Yields the following record types extracted from
        LaunchDaemon plist files:

        .. code-block:: text

            LauncherRecord:
                label (string): Unique identifier for the daemon in launchd.
                program (string): Absolute executable path used with execv(3).
                program_arguments (string[]): Argument vector passed with execvp(3).
                keep_alive (string): Defines whether the daemon should remain running or
                    restart under specified conditions.
                on_demand (boolean): Deprecated; false implies KeepAlive behavior.
                disabled (string): Indicates whether the daemon is disabled by default.
                run_at_load (boolean): Starts the daemon immediately when loaded.
                launch_only_once (boolean): Ensures the daemon is only executed one time.
                process_type (string): Declares job classification influencing system resource limits.
                wait (boolean): inetd-style behavior for socket handling.
                limit_load_to_developer_mode (boolean): Restricts loading based on developer mode.
                limit_load_to_variant (string): Restricts loading to a system variant.
                limit_load_from_variant (string): Prevents loading on a system variant.
                limit_load_to_boot_mode (string[]): Restricts loading to specific boot modes.
                limit_load_from_boot_mode (string): Prevents loading on specific boot modes.
                limit_load_to_hardware (string[]): Restricts loading to specific hardware values.
                limit_load_from_hardware (string[]): Prevents loading on specified hardware.
                launch_events (string[]): Defines event sources that trigger daemon launch.
                mach_services (string[]): Mach services advertised to the bootstrap namespace.
                enable_pressured_exit (string): Enables system-managed termination under memory pressure.
                enable_transactions (boolean): Enables XPC transaction tracking for controlled shutdown.
                environment_variables (string[]): Environment variables set before execution.
                user_name (string): User account used to run the daemon.
                init_groups (boolean): Indicates if initgroups(3) is used for group setup.
                group_name (string): Group under which the daemon runs.
                start_interval (varint): Interval-based execution timing.
                start_calendar_interval (string[]): Calendar-based scheduling rules.
                throttle_interval (varint): Minimum delay between successive launches.
                enable_globbing (boolean): Enables glob(3) expansion of arguments.
                standard_in_path (string): File path mapped to stdin.
                standard_out_path (string): File path mapped to stdout.
                standard_error_path (string): File path mapped to stderr.
                nice (varint): CPU scheduling priority.
                abandon_process_group (boolean): Prevents launchd from terminating child processes.
                low_priority_io (boolean): Applies low-priority I/O classification.
                root_directory (string): Directory used as chroot environment.
                working_directory (string): Working directory before execution.
                umask (varint): File creation mask applied to the process.
                time_out (varint): Deprecated idle timeout setting.
                exit_time_out (varint): Delay before SIGKILL after SIGTERM.
                watch_paths (string[]): Launch triggers based on filesystem changes.
                queue_directories (string[]): Keeps daemon running while directories contain files.
                start_on_mount (boolean): Starts daemon when filesystems are mounted.
                soft_resource_limits (string[]): Soft resource limits applied via setrlimit(2).
                hard_resource_limits (string[]): Hard resource limits applied via setrlimit(2).
                debug (boolean): Enables debug logging in launchd for this job.
                wait_for_debugger (boolean): Starts process suspended for debugger attachment.

            SocketRecord:
                socket_key (string): Identifier for grouping socket definitions.
                sock_type (string): Socket type used when creating the descriptor.
                sock_passive (boolean): Indicates if the socket is listening or connecting.
                sock_node_name (string): Address used when binding or connecting.
                sock_service_name (string): Port or service name for the socket.
                sock_family (string): Address family used for socket creation.
                sock_protocol (string): Protocol associated with the socket.
                sock_path_mode (varint): Permissions applied to socket file.
                sock_path_name (string): Filesystem location for the socket.
                secure_socket_with_key (string): Environment variable referencing generated socket path.
                sock_path_owner (varint): Owner user ID of the socket file.
                sock_path_group (varint): Group ID of the socket file.
                bonjour (string): Optional Bonjour registration.
                multicast_group (string): Multicast group subscription.

            ListenersRecord:
                listeners (string[]): Identifiers referring to defined socket groups.
        """
        yield from build_plist_records(
            self, self.launch_daemon_files, LaunchDaemonRecords, COLLAPSE_PATHS, FIELD_MAPPINGS
        )
