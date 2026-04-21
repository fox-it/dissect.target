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
        results.sort(key=lambda r: (r.source, getattr(r, "plist_path", "")))

        assert len(results) == 4

        assert results[0].hostname == "localhost"
        assert results[0].domain is None
        assert results[0].Label == "com.apple.sidecar-display-agent"
        assert results[0].Disabled is None
        assert results[0].UserName is None
        assert results[0].GroupName is None
        assert results[0].Group is None
        assert results[0].CFBundleIdentifier is None
        assert results[0].CFBundleDevelopmentRegion is None
        assert results[0].CFBundleInfoDictionaryVersion is None
        assert results[0].CFBundleName is None
        assert results[0].InitGroups is None
        assert results[0].Program == "/usr/libexec/SidecarDisplayAgent"
        assert results[0].BundleProgram is None
        assert results[0].ProgramArguments == []
        assert results[0].EnableGlobbing is None
        assert results[0].EnableTransactions
        assert results[0].PressuredExit is None
        assert results[0].EnablePressureExit is None
        assert results[0].EnablePressuredExit == "True"
        assert results[0].KeepAlive is None
        assert results[0].SuccessfulExit is None
        assert results[0].Crashed is None
        assert results[0].RunAtLoad is None
        assert results[0].RootDirectory is None
        assert results[0].WorkingDirectory is None
        assert results[0].Umask is None
        assert results[0].TimeOut is None
        assert results[0].ExitTimeOut is None
        assert results[0].ThrottleInterval is None
        assert results[0].StartInterval is None
        assert results[0].StartOnMount is None
        assert results[0].WatchPaths == []
        assert results[0].QueueDirectories == []
        assert results[0].StandardInPath is None
        assert results[0].StandardOutPath is None
        assert results[0].StandardErrorPath is None
        assert results[0].Debug is None
        assert results[0].WaitForDebugger is None
        assert results[0].Nice is None
        assert results[0].ProcessType == "Interactive"
        assert results[0].PowerNap is None
        assert results[0].AbandonProcessGroup is None
        assert results[0].LowPriorityIO is None
        assert results[0].LowPriorityBackgroundIO is None
        assert results[0].MaterializeDatalessFiles is None
        assert results[0].LaunchOnlyOnce is None
        assert results[0].BootShell is None
        assert results[0].SessionCreate is None
        assert results[0].LegacyTimers is None
        assert results[0].TransactionTimeLimitEnabled is None
        assert results[0].LimitLoadToDeveloperMode is None
        assert results[0].LimitLoadToSessionType is None
        assert results[0].Wait is None
        assert results[0].AssociatedBundleIdentifiers == []
        assert results[0].plist_path is None
        assert results[0].POSIXSpawnType is None
        assert results[0].PosixSpawnType is None
        assert results[0].MultipleInstances is None
        assert results[0].DisabledInSafeBoot is None
        assert results[0].BeginTransactionAtShutdown is None
        assert results[0].OnDemand is None
        assert results[0].AlwaysSIGTERMOnShutdown is None
        assert results[0].MinimalBootProfiles is None
        assert results[0].MinimalBootProfile is None
        assert results[0].LSBackgroundOnly is None
        assert results[0].HopefullyExitsLast is None
        assert results[0].ExponentialThrottling is None
        assert results[0].IgnoreProcessGroupAtShutdown is None
        assert results[0].EventMonitor is None
        assert results[0].AuxiliaryBootstrapper is None
        assert results[0].AuxiliaryBootstrapperAllowDemand is None
        assert results[0].DrainMessagesAfterFailedInit is None
        assert results[0].DrainMessagesOnFailedInit is None
        assert results[0].LimitLoadFromVariant is None
        assert results[0].LimitLoadFromBootMode is None
        assert results[0].EfficiencyMode is None
        assert results[0].Conclave is None
        assert results[0].LaunchEvents == []
        assert results[0].MachServices == ["('com.apple.sidecar-display-agent', True)"]
        assert results[0].SoftResourceLimits == []
        assert results[0].HardResourceLimits == []
        assert results[0].EnvironmentVariables == []
        assert results[0].NoEnvironmentVariables == []
        assert results[0].NO_EnvironmentVariables == []
        assert results[0].SHAuthorizationRight is None
        assert results[0].PublishesEvents is None
        assert results[0].LimitLoadToVariant is None
        assert results[0].RunLoopType is None
        assert results[0].RemoteServices == []
        assert results[0].JetsamProperties == []
        assert results[0].LimitLoadToHardware == []
        assert results[0].PanicOnCrash == []
        assert results[0].LimitLoadToBootMode == []
        assert results[0].Cryptex is None
        assert results[0].ServiceType is None
        assert results[0].ServiceIPC is None
        assert results[0].UrgentLogSubmission == []
        assert results[0].AppIntents == []
        assert results[0].BinaryOrderPreference == []
        assert results[0].LimitLoadFromHardware == []
        assert results[0].StartCalendarInterval == []
        assert results[0].AdditionalProperties == []
        assert results[0].NSAppTransportSecurity == []
        assert results[0].source == "/Library/LaunchAgents/com.apple.sidecar-hid-relay.plist"

        assert results[1].hostname == "localhost"
        assert results[1].domain is None
        assert results[1].Label == "com.apple.AMPArtworkAgent"
        assert results[1].Disabled is None
        assert results[1].UserName is None
        assert results[1].GroupName is None
        assert results[1].Group is None
        assert results[1].CFBundleIdentifier is None
        assert results[1].CFBundleDevelopmentRegion is None
        assert results[1].CFBundleInfoDictionaryVersion is None
        assert results[1].CFBundleName is None
        assert results[1].InitGroups is None
        assert results[1].Program is None
        assert results[1].BundleProgram is None
        assert results[1].ProgramArguments == [
            "/System/Library/PrivateFrameworks/AMPLibrary.framework/Versions/A/Support/AMPArtworkAgent",
            "--launchd",
        ]
        assert results[1].EnableGlobbing is None
        assert results[1].EnableTransactions
        assert results[1].PressuredExit is None
        assert results[1].EnablePressureExit is None
        assert results[1].EnablePressuredExit == "True"
        assert results[1].KeepAlive is None
        assert results[1].SuccessfulExit is None
        assert results[1].Crashed is None
        assert results[1].RunAtLoad is None
        assert results[1].RootDirectory is None
        assert results[1].WorkingDirectory is None
        assert results[1].Umask is None
        assert results[1].TimeOut is None
        assert results[1].ExitTimeOut is None
        assert results[1].ThrottleInterval is None
        assert results[1].StartInterval is None
        assert results[1].StartOnMount is None
        assert results[1].WatchPaths == []
        assert results[1].QueueDirectories == []
        assert results[1].StandardInPath is None
        assert results[1].StandardOutPath is None
        assert results[1].StandardErrorPath is None
        assert results[1].Debug is None
        assert results[1].WaitForDebugger is None
        assert results[1].Nice is None
        assert results[1].ProcessType == "Adaptive"
        assert results[1].PowerNap is None
        assert results[1].AbandonProcessGroup is None
        assert results[1].LowPriorityIO is None
        assert results[1].LowPriorityBackgroundIO is None
        assert results[1].MaterializeDatalessFiles is None
        assert results[1].LaunchOnlyOnce is None
        assert results[1].BootShell is None
        assert results[1].SessionCreate is None
        assert results[1].LegacyTimers is None
        assert results[1].TransactionTimeLimitEnabled is None
        assert results[1].LimitLoadToDeveloperMode is None
        assert results[1].LimitLoadToSessionType is None
        assert results[1].Wait is None
        assert results[1].AssociatedBundleIdentifiers == []
        assert results[1].plist_path is None
        assert results[1].POSIXSpawnType is None
        assert results[1].PosixSpawnType is None
        assert results[1].MultipleInstances is None
        assert results[1].DisabledInSafeBoot is None
        assert results[1].BeginTransactionAtShutdown is None
        assert results[1].OnDemand is None
        assert results[1].AlwaysSIGTERMOnShutdown is None
        assert results[1].MinimalBootProfiles is None
        assert results[1].MinimalBootProfile is None
        assert results[1].LSBackgroundOnly is None
        assert results[1].HopefullyExitsLast is None
        assert results[1].ExponentialThrottling is None
        assert results[1].IgnoreProcessGroupAtShutdown is None
        assert results[1].EventMonitor is None
        assert results[1].AuxiliaryBootstrapper is None
        assert results[1].AuxiliaryBootstrapperAllowDemand is None
        assert results[1].DrainMessagesAfterFailedInit is None
        assert results[1].DrainMessagesOnFailedInit is None
        assert results[1].LimitLoadFromVariant is None
        assert results[1].LimitLoadFromBootMode is None
        assert results[1].EfficiencyMode is None
        assert results[1].Conclave is None
        assert results[1].LaunchEvents == []
        assert results[1].MachServices == ["('com.apple.amp.artworkd', True)"]
        assert results[1].SoftResourceLimits == []
        assert results[1].HardResourceLimits == []
        assert results[1].EnvironmentVariables == []
        assert results[1].NoEnvironmentVariables == []
        assert results[1].NO_EnvironmentVariables == []
        assert results[1].SHAuthorizationRight is None
        assert results[1].PublishesEvents is None
        assert results[1].LimitLoadToVariant is None
        assert results[1].RunLoopType is None
        assert results[1].RemoteServices == []
        assert results[1].JetsamProperties == []
        assert results[1].LimitLoadToHardware == []
        assert results[1].PanicOnCrash == []
        assert results[1].LimitLoadToBootMode == []
        assert results[1].Cryptex is None
        assert results[1].ServiceType is None
        assert results[1].ServiceIPC is None
        assert results[1].UrgentLogSubmission == []
        assert results[1].AppIntents == []
        assert results[1].BinaryOrderPreference == []
        assert results[1].LimitLoadFromHardware == []
        assert results[1].StartCalendarInterval == []
        assert results[1].AdditionalProperties == []
        assert results[1].NSAppTransportSecurity == []
        assert results[1].source == "/System/Library/LaunchAgents/com.apple.AMPArtworkAgent.plist"

        assert results[2].hostname == "localhost"
        assert results[2].domain is None
        assert results[2].Label == "com.apple.familynotificationd"
        assert results[2].Disabled is None
        assert results[2].UserName is None
        assert results[2].GroupName is None
        assert results[2].Group is None
        assert results[2].CFBundleIdentifier is None
        assert results[2].CFBundleDevelopmentRegion is None
        assert results[2].CFBundleInfoDictionaryVersion is None
        assert results[2].CFBundleName is None
        assert results[2].InitGroups is None
        assert (
            results[2].Program == "/System/Library/PrivateFrameworks/FamilyNotification.framework/familynotificationd"
        )
        assert results[2].BundleProgram is None
        assert results[2].ProgramArguments == []
        assert results[2].EnableGlobbing is None
        assert results[2].EnableTransactions
        assert results[2].PressuredExit is None
        assert results[2].EnablePressureExit is None
        assert results[2].EnablePressuredExit is None
        assert results[2].KeepAlive is None
        assert results[2].SuccessfulExit is None
        assert results[2].Crashed is None
        assert results[2].RunAtLoad is None
        assert results[2].RootDirectory is None
        assert results[2].WorkingDirectory is None
        assert results[2].Umask is None
        assert results[2].TimeOut is None
        assert results[2].ExitTimeOut == 1
        assert results[2].ThrottleInterval is None
        assert results[2].StartInterval is None
        assert results[2].StartOnMount is None
        assert results[2].WatchPaths == []
        assert results[2].QueueDirectories == []
        assert results[2].StandardInPath is None
        assert results[2].StandardOutPath is None
        assert results[2].StandardErrorPath is None
        assert results[2].Debug is None
        assert results[2].WaitForDebugger is None
        assert results[2].Nice is None
        assert results[2].ProcessType is None
        assert results[2].PowerNap is None
        assert results[2].AbandonProcessGroup is None
        assert results[2].LowPriorityIO is None
        assert results[2].LowPriorityBackgroundIO is None
        assert results[2].MaterializeDatalessFiles is None
        assert results[2].LaunchOnlyOnce is None
        assert results[2].BootShell is None
        assert results[2].SessionCreate is None
        assert results[2].LegacyTimers is None
        assert results[2].TransactionTimeLimitEnabled is None
        assert results[2].LimitLoadToDeveloperMode is None
        assert results[2].LimitLoadToSessionType == "['LoginWindow', 'Aqua']"
        assert results[2].Wait is None
        assert results[2].AssociatedBundleIdentifiers == []
        assert results[2].plist_path is None
        assert results[2].POSIXSpawnType == "Adaptive"
        assert results[2].PosixSpawnType is None
        assert results[2].MultipleInstances is None
        assert results[2].DisabledInSafeBoot is None
        assert results[2].BeginTransactionAtShutdown is None
        assert results[2].OnDemand is None
        assert results[2].AlwaysSIGTERMOnShutdown is None
        assert results[2].MinimalBootProfiles is None
        assert results[2].MinimalBootProfile is None
        assert results[2].LSBackgroundOnly is None
        assert results[2].HopefullyExitsLast is None
        assert results[2].ExponentialThrottling is None
        assert results[2].IgnoreProcessGroupAtShutdown is None
        assert results[2].EventMonitor is None
        assert results[2].AuxiliaryBootstrapper is None
        assert results[2].AuxiliaryBootstrapperAllowDemand is None
        assert results[2].DrainMessagesAfterFailedInit is None
        assert results[2].DrainMessagesOnFailedInit is None
        assert results[2].LimitLoadFromVariant is None
        assert results[2].LimitLoadFromBootMode is None
        assert results[2].EfficiencyMode is None
        assert results[2].Conclave is None
        assert results[2].LaunchEvents != []
        assert results[2].MachServices == [
            "('com.apple.familynotification.agent', True)",
            "('com.apple.usernotifications.delegate.com.apple.familynotifications', True)",
        ]
        assert results[2].SoftResourceLimits == []
        assert results[2].HardResourceLimits == []
        assert results[2].EnvironmentVariables == []
        assert results[2].NoEnvironmentVariables == []
        assert results[2].NO_EnvironmentVariables == []
        assert results[2].SHAuthorizationRight is None
        assert results[2].PublishesEvents is None
        assert results[2].LimitLoadToVariant is None
        assert results[2].RunLoopType is None
        assert results[2].RemoteServices == []
        assert results[2].JetsamProperties == []
        assert results[2].LimitLoadToHardware == []
        assert results[2].PanicOnCrash == []
        assert results[2].LimitLoadToBootMode == []
        assert results[2].Cryptex is None
        assert results[2].ServiceType is None
        assert results[2].ServiceIPC is None
        assert results[2].UrgentLogSubmission == []
        assert results[2].AppIntents == []
        assert results[2].BinaryOrderPreference == []
        assert results[2].LimitLoadFromHardware == []
        assert results[2].StartCalendarInterval == []
        assert results[2].AdditionalProperties == []
        assert results[2].NSAppTransportSecurity == []
        assert results[2].source == "/System/Library/LaunchAgents/com.apple.familynotificationd.plist"

        assert results[3].hostname == "localhost"
        assert results[3].domain is None
        assert results[3].Label == "com.apple.seserviced"
        assert results[3].Disabled is None
        assert results[3].UserName is None
        assert results[3].GroupName is None
        assert results[3].Group is None
        assert results[3].CFBundleIdentifier is None
        assert results[3].CFBundleDevelopmentRegion is None
        assert results[3].CFBundleInfoDictionaryVersion is None
        assert results[3].CFBundleName is None
        assert results[3].InitGroups is None
        assert results[3].Program == "/usr/libexec/seserviced"
        assert results[3].BundleProgram is None
        assert results[3].ProgramArguments == []
        assert results[3].EnableGlobbing is None
        assert results[3].EnableTransactions
        assert results[3].PressuredExit is None
        assert results[3].EnablePressureExit is None
        assert results[3].EnablePressuredExit == "True"
        assert results[3].KeepAlive is None
        assert results[3].SuccessfulExit is None
        assert results[3].Crashed is None
        assert results[3].RunAtLoad is None
        assert results[3].RootDirectory is None
        assert results[3].WorkingDirectory is None
        assert results[3].Umask is None
        assert results[3].TimeOut is None
        assert results[3].ExitTimeOut is None
        assert results[3].ThrottleInterval is None
        assert results[3].StartInterval is None
        assert results[3].StartOnMount is None
        assert results[3].WatchPaths == []
        assert results[3].QueueDirectories == []
        assert results[3].StandardInPath is None
        assert results[3].StandardOutPath is None
        assert results[3].StandardErrorPath is None
        assert results[3].Debug is None
        assert results[3].WaitForDebugger is None
        assert results[3].Nice is None
        assert results[3].ProcessType == "Adaptive"
        assert results[3].PowerNap is None
        assert results[3].AbandonProcessGroup is None
        assert results[3].LowPriorityIO is None
        assert results[3].LowPriorityBackgroundIO is None
        assert results[3].MaterializeDatalessFiles is None
        assert results[3].LaunchOnlyOnce is None
        assert results[3].BootShell is None
        assert results[3].SessionCreate is None
        assert results[3].LegacyTimers is None
        assert results[3].TransactionTimeLimitEnabled is None
        assert results[3].LimitLoadToDeveloperMode is None
        assert results[3].LimitLoadToSessionType == "['Aqua']"
        assert results[3].Wait is None
        assert results[3].AssociatedBundleIdentifiers == []
        assert results[3].plist_path is None
        assert results[3].POSIXSpawnType is None
        assert results[3].PosixSpawnType is None
        assert results[3].MultipleInstances is None
        assert results[3].DisabledInSafeBoot is None
        assert results[3].BeginTransactionAtShutdown is None
        assert results[3].OnDemand is None
        assert results[3].AlwaysSIGTERMOnShutdown is None
        assert results[3].MinimalBootProfiles is None
        assert results[3].MinimalBootProfile is None
        assert results[3].LSBackgroundOnly is None
        assert results[3].HopefullyExitsLast is None
        assert results[3].ExponentialThrottling is None
        assert results[3].IgnoreProcessGroupAtShutdown is None
        assert results[3].EventMonitor is None
        assert results[3].AuxiliaryBootstrapper is None
        assert results[3].AuxiliaryBootstrapperAllowDemand is None
        assert results[3].DrainMessagesAfterFailedInit is None
        assert results[3].DrainMessagesOnFailedInit is None
        assert results[3].LimitLoadFromVariant == "HasFactoryContent"
        assert results[3].LimitLoadFromBootMode is None
        assert results[3].EfficiencyMode is None
        assert results[3].Conclave is None
        assert results[3].LaunchEvents != []
        assert results[3].MachServices == [
            "('com.apple.seserviced', True)",
            "('com.apple.seserviced.sereservation.client', True)",
        ]
        assert results[3].SoftResourceLimits == []
        assert results[3].HardResourceLimits == []
        assert results[3].EnvironmentVariables == []
        assert results[3].NoEnvironmentVariables == []
        assert results[3].NO_EnvironmentVariables == []
        assert results[3].SHAuthorizationRight is None
        assert results[3].PublishesEvents is None
        assert results[3].LimitLoadToVariant is None
        assert results[3].RunLoopType is None
        assert results[3].RemoteServices == []
        assert results[3].JetsamProperties == []
        assert results[3].LimitLoadToHardware == []
        assert results[3].PanicOnCrash == []
        assert results[3].LimitLoadToBootMode == []
        assert results[3].Cryptex is None
        assert results[3].ServiceType is None
        assert results[3].ServiceIPC is None
        assert results[3].UrgentLogSubmission == []
        assert results[3].AppIntents == []
        assert results[3].BinaryOrderPreference == []
        assert results[3].LimitLoadFromHardware == []
        assert results[3].StartCalendarInterval == []
        assert results[3].AdditionalProperties == []
        assert results[3].NSAppTransportSecurity == []
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
        results.sort(key=lambda r: (r.source, getattr(r, "plist_path", "")))

        assert len(results) == 3

        assert results[0].hostname == "localhost"
        assert results[0].domain is None
        assert results[0].Label == "com.apple.perfpowermetricd"
        assert results[0].Disabled is None
        assert results[0].UserName is None
        assert results[0].GroupName is None
        assert results[0].Group is None
        assert results[0].CFBundleIdentifier is None
        assert results[0].CFBundleDevelopmentRegion is None
        assert results[0].CFBundleInfoDictionaryVersion is None
        assert results[0].CFBundleName is None
        assert results[0].InitGroups is None
        assert results[0].Program is None
        assert results[0].BundleProgram is None
        assert results[0].ProgramArguments == ["usr/libexec/perfpowermetricd"] or results[0].ProgramArguments == [
            "/usr/libexec/perfpowermetricd"
        ]
        assert results[0].EnableGlobbing is None
        assert results[0].EnableTransactions
        assert results[0].PressuredExit is None
        assert results[0].EnablePressureExit is None
        assert results[0].EnablePressuredExit == "True"
        assert results[0].KeepAlive is None
        assert results[0].SuccessfulExit is None
        assert results[0].Crashed is None
        assert results[0].RunAtLoad is None
        assert results[0].RootDirectory is None
        assert results[0].WorkingDirectory is None
        assert results[0].Umask is None
        assert results[0].TimeOut is None
        assert results[0].ExitTimeOut is None
        assert results[0].ThrottleInterval is None
        assert results[0].StartInterval is None
        assert results[0].StartOnMount is None
        assert results[0].WatchPaths == []
        assert results[0].QueueDirectories == []
        assert results[0].StandardInPath is None
        assert results[0].StandardOutPath is None
        assert results[0].StandardErrorPath is None
        assert results[0].Debug is None
        assert results[0].WaitForDebugger is None
        assert results[0].Nice is None
        assert results[0].ProcessType == "Interactive"
        assert results[0].PowerNap is None
        assert results[0].AbandonProcessGroup is None
        assert results[0].LowPriorityIO is None
        assert results[0].LowPriorityBackgroundIO is None
        assert results[0].MaterializeDatalessFiles is None
        assert results[0].LaunchOnlyOnce is None
        assert results[0].BootShell is None
        assert results[0].SessionCreate is None
        assert results[0].LegacyTimers is None
        assert results[0].TransactionTimeLimitEnabled is None
        assert results[0].LimitLoadToDeveloperMode is None
        assert results[0].LimitLoadToSessionType is None
        assert results[0].Wait is None
        assert results[0].AssociatedBundleIdentifiers == []
        assert results[0].plist_path is None
        assert results[0].POSIXSpawnType is None
        assert results[0].PosixSpawnType is None
        assert results[0].MultipleInstances is None
        assert results[0].DisabledInSafeBoot is None
        assert results[0].BeginTransactionAtShutdown is None
        assert results[0].OnDemand is None
        assert results[0].AlwaysSIGTERMOnShutdown is None
        assert results[0].MinimalBootProfiles is None
        assert results[0].MinimalBootProfile is None
        assert results[0].LSBackgroundOnly is None
        assert results[0].HopefullyExitsLast is None
        assert results[0].ExponentialThrottling is None
        assert results[0].IgnoreProcessGroupAtShutdown is None
        assert results[0].EventMonitor is None
        assert results[0].AuxiliaryBootstrapper is None
        assert results[0].AuxiliaryBootstrapperAllowDemand is None
        assert results[0].DrainMessagesAfterFailedInit is None
        assert results[0].DrainMessagesOnFailedInit is None
        assert results[0].LimitLoadFromVariant is None
        assert results[0].LimitLoadFromBootMode is None
        assert results[0].EfficiencyMode is None
        assert results[0].Conclave is None
        assert results[0].LaunchEvents == []
        assert results[0].MachServices == ["('com.apple.PerfPowerMetricMonitor.xpc', True)"]
        assert results[0].SoftResourceLimits == []
        assert results[0].HardResourceLimits == []
        assert results[0].EnvironmentVariables == []
        assert results[0].NoEnvironmentVariables == []
        assert results[0].NO_EnvironmentVariables == []
        assert results[0].SHAuthorizationRight is None
        assert results[0].PublishesEvents is None
        assert results[0].LimitLoadToVariant is None
        assert results[0].RunLoopType is None
        assert results[0].RemoteServices == []
        assert results[0].JetsamProperties == []
        assert results[0].LimitLoadToHardware == []
        assert results[0].PanicOnCrash == []
        assert results[0].LimitLoadToBootMode == []
        assert results[0].Cryptex is None
        assert results[0].ServiceType is None
        assert results[0].ServiceIPC is None
        assert results[0].UrgentLogSubmission == []
        assert results[0].AppIntents == []
        assert results[0].BinaryOrderPreference == []
        assert results[0].LimitLoadFromHardware == []
        assert results[0].StartCalendarInterval == []
        assert results[0].AdditionalProperties == []
        assert results[0].NSAppTransportSecurity == []
        assert results[0].source == "/Library/LaunchDaemons/com.apple.perfpowermetricd.plist"

        assert results[1].hostname == "localhost"
        assert results[1].domain is None
        assert results[1].Label == "com.apple.WirelessRadioManager"
        assert results[1].Disabled is None
        assert results[1].UserName is None
        assert results[1].GroupName is None
        assert results[1].Group is None
        assert results[1].CFBundleIdentifier is None
        assert results[1].CFBundleDevelopmentRegion is None
        assert results[1].CFBundleInfoDictionaryVersion is None
        assert results[1].CFBundleName is None
        assert results[1].InitGroups is None
        assert results[1].Program is None
        assert results[1].BundleProgram is None
        assert results[1].ProgramArguments == ["/usr/sbin/WirelessRadioManagerd"]
        assert results[1].EnableGlobbing is None
        assert results[1].EnableTransactions is None
        assert results[1].PressuredExit is None
        assert results[1].EnablePressureExit is None
        assert results[1].EnablePressuredExit == "True"
        assert results[1].KeepAlive is None
        assert results[1].SuccessfulExit is None
        assert results[1].Crashed is None
        assert results[1].RunAtLoad is None
        assert results[1].RootDirectory is None
        assert results[1].WorkingDirectory is None
        assert results[1].Umask is None
        assert results[1].TimeOut is None
        assert results[1].ExitTimeOut is None
        assert results[1].ThrottleInterval == 10
        assert results[1].StartInterval is None
        assert results[1].StartOnMount is None
        assert results[1].WatchPaths == []
        assert results[1].QueueDirectories == []
        assert results[1].StandardInPath is None
        assert results[1].StandardOutPath is None
        assert results[1].StandardErrorPath is None
        assert results[1].Debug is None
        assert results[1].WaitForDebugger is None
        assert results[1].Nice is None
        assert results[1].ProcessType is None
        assert results[1].PowerNap is None
        assert results[1].AbandonProcessGroup is None
        assert results[1].LowPriorityIO is None
        assert results[1].LowPriorityBackgroundIO is None
        assert results[1].MaterializeDatalessFiles is None
        assert results[1].LaunchOnlyOnce is None
        assert results[1].BootShell is None
        assert results[1].SessionCreate is None
        assert results[1].LegacyTimers is None
        assert results[1].TransactionTimeLimitEnabled is None
        assert results[1].LimitLoadToDeveloperMode is None
        assert results[1].LimitLoadToSessionType is None
        assert results[1].Wait is None
        assert results[1].AssociatedBundleIdentifiers == []
        assert results[1].plist_path is None
        assert results[1].POSIXSpawnType == "Interactive"
        assert results[1].PosixSpawnType is None
        assert results[1].MultipleInstances is None
        assert results[1].DisabledInSafeBoot is None
        assert results[1].BeginTransactionAtShutdown is None
        assert results[1].OnDemand is None
        assert results[1].AlwaysSIGTERMOnShutdown is None
        assert results[1].MinimalBootProfiles is None
        assert results[1].MinimalBootProfile is None
        assert results[1].LSBackgroundOnly is None
        assert results[1].HopefullyExitsLast is None
        assert results[1].ExponentialThrottling is None
        assert results[1].IgnoreProcessGroupAtShutdown is None
        assert results[1].EventMonitor is None
        assert results[1].AuxiliaryBootstrapper is None
        assert results[1].AuxiliaryBootstrapperAllowDemand is None
        assert results[1].DrainMessagesAfterFailedInit is None
        assert results[1].DrainMessagesOnFailedInit is None
        assert results[1].LimitLoadFromVariant is None
        assert results[1].LimitLoadFromBootMode is None
        assert results[1].EfficiencyMode is None
        assert results[1].Conclave is None
        assert results[1].LaunchEvents == []
        assert results[1].MachServices == [
            "('com.apple.WirelessCoexManager', True)",
            "('com.apple.WirelessRadioManager', True)",
        ]
        assert results[1].SoftResourceLimits == []
        assert results[1].HardResourceLimits == []
        assert results[1].EnvironmentVariables == []
        assert results[1].NoEnvironmentVariables == []
        assert results[1].NO_EnvironmentVariables == []
        assert results[1].SHAuthorizationRight is None
        assert results[1].PublishesEvents is None
        assert results[1].LimitLoadToVariant is None
        assert results[1].RunLoopType is None
        assert results[1].RemoteServices == []
        assert results[1].JetsamProperties == []
        assert results[1].LimitLoadToHardware == []
        assert results[1].PanicOnCrash == []
        assert results[1].LimitLoadToBootMode == []
        assert results[1].Cryptex is None
        assert results[1].ServiceType is None
        assert results[1].ServiceIPC is None
        assert results[1].UrgentLogSubmission == []
        assert results[1].AppIntents == []
        assert results[1].BinaryOrderPreference == []
        assert results[1].LimitLoadFromHardware == []
        assert results[1].StartCalendarInterval == []
        assert results[1].AdditionalProperties == []
        assert results[1].NSAppTransportSecurity == []
        assert results[1].source == "/System/Library/LaunchDaemons/com.apple.WirelessRadioManager-osx.plist"

        assert results[2].hostname == "localhost"
        assert results[2].domain is None
        assert results[2].Label == "com.apple.cfprefsd.xpc.daemon"
        assert results[2].Disabled is None
        assert results[2].UserName is None
        assert results[2].GroupName is None
        assert results[2].Group is None
        assert results[2].CFBundleIdentifier is None
        assert results[2].CFBundleDevelopmentRegion is None
        assert results[2].CFBundleInfoDictionaryVersion is None
        assert results[2].CFBundleName is None
        assert results[2].InitGroups is None
        assert results[2].Program is None
        assert results[2].BundleProgram is None
        assert results[2].ProgramArguments == ["/usr/sbin/cfprefsd", "daemon"]
        assert results[2].EnableGlobbing is None
        assert results[2].EnableTransactions
        assert results[2].PressuredExit is None
        assert results[2].EnablePressureExit is None
        assert results[2].EnablePressuredExit == "False"
        assert results[2].KeepAlive is None
        assert results[2].SuccessfulExit is None
        assert results[2].Crashed is None
        assert results[2].RunAtLoad is None
        assert results[2].RootDirectory is None
        assert results[2].WorkingDirectory is None
        assert results[2].Umask is None
        assert results[2].TimeOut is None
        assert results[2].ExitTimeOut is None
        assert results[2].ThrottleInterval is None
        assert results[2].StartInterval is None
        assert results[2].StartOnMount is None
        assert results[2].WatchPaths == []
        assert results[2].QueueDirectories == []
        assert results[2].StandardInPath is None
        assert results[2].StandardOutPath is None
        assert results[2].StandardErrorPath is None
        assert results[2].Debug is None
        assert results[2].WaitForDebugger is None
        assert results[2].Nice is None
        assert results[2].ProcessType is None
        assert results[2].PowerNap is None
        assert results[2].AbandonProcessGroup is None
        assert results[2].LowPriorityIO is None
        assert results[2].LowPriorityBackgroundIO is None
        assert results[2].MaterializeDatalessFiles is None
        assert results[2].LaunchOnlyOnce is None
        assert results[2].BootShell is None
        assert results[2].SessionCreate is None
        assert results[2].LegacyTimers is None
        assert results[2].TransactionTimeLimitEnabled is None
        assert results[2].LimitLoadToDeveloperMode is None
        assert results[2].LimitLoadToSessionType is None
        assert results[2].Wait is None
        assert results[2].AssociatedBundleIdentifiers == []
        assert results[2].plist_path is None
        assert results[2].POSIXSpawnType == "Adaptive"
        assert results[2].PosixSpawnType is None
        assert results[2].MultipleInstances is None
        assert results[2].DisabledInSafeBoot is None
        assert results[2].BeginTransactionAtShutdown is None
        assert results[2].OnDemand is None
        assert results[2].AlwaysSIGTERMOnShutdown is None
        assert results[2].MinimalBootProfiles is None
        assert results[2].MinimalBootProfile is None
        assert results[2].LSBackgroundOnly is None
        assert results[2].HopefullyExitsLast is None
        assert results[2].ExponentialThrottling is None
        assert results[2].IgnoreProcessGroupAtShutdown is None
        assert results[2].EventMonitor is None
        assert results[2].AuxiliaryBootstrapper is None
        assert results[2].AuxiliaryBootstrapperAllowDemand is None
        assert results[2].DrainMessagesAfterFailedInit is None
        assert results[2].DrainMessagesOnFailedInit is None
        assert results[2].LimitLoadFromVariant is None
        assert results[2].LimitLoadFromBootMode is None
        assert results[2].EfficiencyMode is None
        assert results[2].Conclave is None
        assert results[2].LaunchEvents == []
        assert results[2].MachServices == ["('com.apple.cfprefsd.daemon', True)"]
        assert results[2].SoftResourceLimits == ["('NumberOfFiles', 512)"]
        assert results[2].HardResourceLimits == ["('NumberOfFiles', 512)"]
        assert results[2].EnvironmentVariables == []
        assert results[2].NoEnvironmentVariables == []
        assert results[2].NO_EnvironmentVariables == []
        assert results[2].SHAuthorizationRight is None
        assert results[2].PublishesEvents is None
        assert results[2].LimitLoadToVariant is None
        assert results[2].RunLoopType is None
        assert results[2].RemoteServices == []
        assert results[2].JetsamProperties == []
        assert results[2].LimitLoadToHardware == []
        assert results[2].PanicOnCrash == []
        assert results[2].LimitLoadToBootMode == []
        assert results[2].Cryptex is None
        assert results[2].ServiceType is None
        assert results[2].ServiceIPC is None
        assert results[2].UrgentLogSubmission == []
        assert results[2].AppIntents == []
        assert results[2].BinaryOrderPreference == []
        assert results[2].LimitLoadFromHardware == []
        assert results[2].StartCalendarInterval == []
        assert results[2].AdditionalProperties == []
        assert results[2].NSAppTransportSecurity == []
        assert results[2].source == "/Users/user/Library/LaunchDaemons/com.apple.cfprefsd.xpc.daemon.plist"
