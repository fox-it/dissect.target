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

LauncherRecord1 = [
    ("string", "Label"),
    ("string", "Disabled"),
    ("string", "UserName"),
    ("string", "GroupName"),
    ("string", "Group"),
    ("string", "CFBundleIdentifier"),
    ("string", "CFBundleDevelopmentRegion"),
    ("string", "CFBundleInfoDictionaryVersion"),
    ("string", "CFBundleName"),
    ("boolean", "InitGroups"),
    ("string", "Program"),
    ("string", "BundleProgram"),
    ("string[]", "ProgramArguments"),
    ("boolean", "EnableGlobbing"),
    ("boolean", "EnableTransactions"),
    ("boolean", "PressuredExit"),
    ("boolean", "EnablePressureExit"),
    ("string", "EnablePressuredExit"),
    ("string", "KeepAlive"),
    ("boolean", "SuccessfulExit"),
    ("boolean", "Crashed"),
    ("boolean", "RunAtLoad"),
    ("string", "RootDirectory"),
    ("string", "WorkingDirectory"),
    ("varint", "Umask"),
    ("varint", "TimeOut"),
    ("varint", "ExitTimeOut"),
    ("varint", "ThrottleInterval"),
    ("varint", "StartInterval"),
    ("boolean", "StartOnMount"),
    ("string[]", "WatchPaths"),
    ("string[]", "QueueDirectories"),
    ("string", "StandardInPath"),
    ("string", "StandardOutPath"),
    ("string", "StandardErrorPath"),
    ("boolean", "Debug"),
    ("boolean", "WaitForDebugger"),
    ("varint", "Nice"),
    ("string", "ProcessType"),
    ("boolean", "PowerNap"),
    ("boolean", "AbandonProcessGroup"),
    ("boolean", "LowPriorityIO"),
    ("boolean", "LowPriorityBackgroundIO"),
    ("boolean", "MaterializeDatalessFiles"),
    ("boolean", "LaunchOnlyOnce"),
    ("boolean", "BootShell"),
    ("boolean", "SessionCreate"),
    ("boolean", "LegacyTimers"),
    ("boolean", "TransactionTimeLimitEnabled"),
    ("boolean", "LimitLoadToDeveloperMode"),
    ("string", "LimitLoadToSessionType"),
    ("boolean", "Wait"),
    ("string[]", "AssociatedBundleIdentifiers"),
    ("string", "plist_path"),
    ("string", "POSIXSpawnType"),
    ("string", "PosixSpawnType"),
    ("string", "MultipleInstances"),
    ("boolean", "DisabledInSafeBoot"),
    ("boolean", "BeginTransactionAtShutdown"),
    ("boolean", "OnDemand"),
    ("boolean", "AlwaysSIGTERMOnShutdown"),
    ("boolean", "MinimalBootProfiles"),
    ("boolean", "MinimalBootProfile"),
    ("boolean", "LSBackgroundOnly"),
    ("boolean", "HopefullyExitsLast"),
    ("boolean", "ExponentialThrottling"),
    ("boolean", "IgnoreProcessGroupAtShutdown"),
    ("boolean", "EventMonitor"),
    ("boolean", "AuxiliaryBootstrapper"),
    ("boolean", "AuxiliaryBootstrapperAllowDemand"),
    ("boolean", "DrainMessagesAfterFailedInit"),
    ("boolean", "DrainMessagesOnFailedInit"),
    ("string", "LimitLoadFromVariant"),
    ("string", "LimitLoadFromBootMode"),
    ("string", "EfficiencyMode"),
    ("string", "Conclave"),
    ("string[]", "LaunchEvents"),
    ("string[]", "MachServices"),
    ("string[]", "SoftResourceLimits"),
    ("string[]", "HardResourceLimits"),
    ("string[]", "EnvironmentVariables"),
    ("string[]", "NoEnvironmentVariables"),
    ("string[]", "NO_EnvironmentVariables"),
    ("string", "SHAuthorizationRight"),
    ("string", "PublishesEvents"),
    ("string", "LimitLoadToVariant"),
    ("string", "RunLoopType"),
    ("string[]", "RemoteServices"),
    ("string[]", "JetsamProperties"),
    ("string[]", "LimitLoadToHardware"),
    ("string[]", "PanicOnCrash"),
    ("string[]", "LimitLoadToBootMode"),
    ("string", "Cryptex"),
    ("string", "ServiceType"),
    ("string", "ServiceIPC"),
    ("string[]", "UrgentLogSubmission"),
    ("string[]", "AppIntents"),
    ("string[]", "BinaryOrderPreference"),
    ("string[]", "LimitLoadFromHardware"),
    ("string[]", "StartCalendarInterval"),
    ("string[]", "AdditionalProperties"),
    ("string[]", "NSAppTransportSecurity"),
    ("string[]", "com_apple_usbcd"),
    ("string[]", "com_apple_private_tcc_allow"),
    ("string[]", "com_apple_security_application_groups"),
    ("string[]", "com_apple_private_security_restricted_application_groups"),
    ("string[]", "com_apple_security_exception_files_home_relative_path_read_write"),
    ("string[]", "com_apple_security_exception_mach_lookup_global_name"),
    ("string[]", "com_apple_security_exception_sysctl_read_only"),
    ("boolean", "com_apple_private_security_no_sandbox"),
    ("boolean", "com_apple_ane_iokit_user_access"),
    ("boolean", "com_apple_alarm"),
    ("boolean", "com_apple_imdpersistence_IMDPersistenceAgent_GroupMetadata"),
    ("boolean", "com_apple_imdpersistence_IMDPersistenceAgent_Syndication"),
    ("path", "source"),
]

LauncherRecord2 = [
    ("boolean", "Wait"),
    ("varint", "Instances"),
    ("string", "plist_path"),
    ("path", "source"),
]

LauncherRecord3 = [
    ("string", "SocketKey"),
    ("string", "SockType"),
    ("boolean", "SockPassive"),
    ("string", "SockNodeName"),
    ("string", "SockServiceName"),
    ("string", "SockFamily"),
    ("string", "SockProtocol"),
    ("varint", "SockPathMode"),
    ("string", "SockPathName"),
    ("string", "SecureSocketWithKey"),
    ("varint", "SockPathOwner"),
    ("varint", "SockPathGroup"),
    ("varint", "SockPathMode"),
    ("string", "Bonjour"),
    ("string", "MulticastGroup"),
    ("boolean", "ReceivePacketInfo"),
    ("string", "plist_path"),
    ("path", "source"),
]

LauncherRecord4 = [
    ("string[]", "Version4"),
    ("path", "source"),
]

LauncherRecord5 = [
    ("boolean", "UNSettingAlerts"),
    ("boolean", "UNSettingAlwaysShowPreviews"),
    ("boolean", "UNSettingLockScreen"),
    ("boolean", "UNSettingModalAlertStyle"),
    ("boolean", "UNAutomaticallyShowSettings"),
    ("boolean", "UNSettingNotificationCenter"),
    ("boolean", "UNDaemonShouldReceiveBackgroundResponses"),
    ("boolean", "UNSuppressUserAuthorizationPrompt"),
    ("string", "plist_path"),
    ("path", "source"),
]

LauncherRecord6 = [
    ("string", "UNNotificationIconDefault"),
    ("string", "UNNotificationIconSettings"),
    ("string", "plist_path"),
    ("path", "source"),
]

LauncherRecord7 = [
    ("string[]", "Listeners"),
    ("string", "plist_path"),
    ("path", "source"),
]

TargetRecordDescriptor(
    "macos/launch_daemons",
    LauncherRecord1,
)

LaunchAgentRecords = (
    TargetRecordDescriptor(
        "macos/launch_agents",
        LauncherRecord1,
    ),
    TargetRecordDescriptor(
        "macos/launch_agents/socket",
        LauncherRecord3,
    ),
    TargetRecordDescriptor(
        "macos/launch_agents/un",
        LauncherRecord5,
    ),
    TargetRecordDescriptor(
        "macos/launch_agents/un_notification",
        LauncherRecord6,
    ),
)

LaunchDaemonRecords = (
    TargetRecordDescriptor(
        "macos/launch_daemons",
        LauncherRecord1,
    ),
    TargetRecordDescriptor(
        "macos/launch_daemons/wait",
        LauncherRecord2,
    ),
    TargetRecordDescriptor(
        "macos/launch_daemons/socket",
        LauncherRecord3,
    ),
    TargetRecordDescriptor(
        "macos/launch_daemons/version4",
        LauncherRecord4,
    ),
    TargetRecordDescriptor(
        "macos/launch_daemons/listeners",
        LauncherRecord7,
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
    # @export(output="yield")
    def launch_agents(self) -> Iterator[LaunchAgentRecords]:
        """Yield macOS launch agent plist files."""
        yield from build_plist_records(self, self.launch_agent_files, LaunchAgentRecords, COLLAPSE_PATHS)

    @export(record=LaunchDaemonRecords)
    def launch_daemons(self) -> Iterator[LaunchDaemonRecords]:
        """Yield macOS launch daemon plist files."""
        yield from build_plist_records(self, self.launch_daemon_files, LaunchDaemonRecords, COLLAPSE_PATHS)
