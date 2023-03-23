from datetime import datetime
from typing import Optional

from dissect.util.ts import from_unix
from flow.record.fieldtypes import uri

from dissect.target.exceptions import RegistryError
from dissect.target.helpers.descriptor_extensions import (
    RegistryRecordDescriptorExtension,
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

UserRegistryRecordDescriptor = create_extended_descriptor(
    [
        RegistryRecordDescriptorExtension,
        UserRecordDescriptorExtension,
    ]
)

AppInitRecord = UserRegistryRecordDescriptor(
    "filesystem/registry/appinit",
    [
        ("datetime", "ts"),
        ("uri", "path"),
    ],
)

KnownDllRecord = UserRegistryRecordDescriptor(
    "filesystem/registry/knowndlls",
    [
        ("datetime", "ts"),
        ("uri", "path"),
    ],
)

SessionManagerRecord = UserRegistryRecordDescriptor(
    "filesystem/registry/sessionmanager",
    [
        ("datetime", "ts"),
        ("uri", "path"),
    ],
)

NullSessionPipeRecord = UserRegistryRecordDescriptor(
    "filesystem/registry/nullsessionpipes",
    [
        ("string", "name"),
    ],
)

NdisRecord = UserRegistryRecordDescriptor(
    "filesystem/registry/ndis",
    [
        ("datetime", "ts"),
        ("string", "network"),
        ("string", "name"),
        ("string", "pnpinstanceid"),
    ],
)

CommandProcAutoRunRecord = UserRegistryRecordDescriptor(
    "filesystem/registry/commandprocautorun",
    [
        ("datetime", "ts"),
        ("uri", "path"),
    ],
)

AlternateShellRecord = UserRegistryRecordDescriptor(
    "filesystem/registry/alternateshell",
    [
        ("datetime", "ts"),
        ("uri", "path"),
    ],
)

BootShellRecord = UserRegistryRecordDescriptor(
    "filesystem/registry/bootshell",
    [
        ("datetime", "ts"),
        ("uri", "path"),
    ],
)

FileRenameOperationRecord = UserRegistryRecordDescriptor(
    "filesystem/registry/filerenameoperations",
    [
        ("datetime", "ts"),
        ("uri", "path"),
    ],
)

WinRarRecord = UserRegistryRecordDescriptor(
    "filesystem/registry/winrar",
    [
        ("datetime", "ts"),
        ("uri", "path"),
    ],
)

WinSockNamespaceProviderRecord = UserRegistryRecordDescriptor(
    "filesystem/registry/winsocknamespaceprovider",
    [
        ("datetime", "ts"),
        ("uri", "librarypath"),
        ("uri", "displaystring"),
        ("bytes", "providerid"),
        ("string", "enabled"),
        ("string", "version"),
    ],
)


class GenericPlugin(Plugin):
    """Generic Windows plugin.

    Provides some plugins that don't fit in a separate plugin.
    """

    def check_compatible(self):
        return self.target.has_function("registry")

    @export(property=True)
    def ntversion(self):
        """Return the Windows NT version."""
        return self.target._os._nt_version()

    @export(output="yield")
    def pathenvironment(self):
        """Return the content of the Windows PATH environment variable.

        PATH is an environment variable on an operating system that specifies a set of directories where executable
        programs are located. Adversaries may add the directories in which they have stored their (malicious) binaries.

        References:
            - https://en.wikipedia.org/wiki/PATH_%28variable%29
        """
        key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"
        for r in self.target.registry.keys(key):
            yield r.value("Path").value

    @export(property=True)
    def domain(self):
        """Return the domain name.

        Corporate Windows systems are usually connected to a domain (active directory).

        References:
            - https://en.wikipedia.org/wiki/Active_Directory
        """
        keys = [
            ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History", "MachineDomain"),
            ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History", "NetworkName"),
            ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History", "DCName"),
            ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Telephony", "DomainName"),
        ]

        for key, value in keys:
            try:
                val = self.target.registry.key(key).value(value).value
                if val:
                    val = val.strip("\\")
                    return val
            except RegistryError:
                continue

    @export(property=True)
    def activity(self) -> Optional[datetime]:
        """Return last seen activity based on filesystem timestamps."""
        last_seen = 0

        try:
            for f in self.target.fs.scandir("sysvol/windows/system32/winevt/logs"):
                if f.stat().st_mtime > last_seen:
                    last_seen = f.stat().st_mtime
        except Exception as e:
            self.target.log.debug("Could not determine last activity", exc_info=e)
            pass

        try:
            for f in self.target.fs.scandir("sysvol/windows/system32/config"):
                if f.stat().st_mtime > last_seen:
                    last_seen = f.stat().st_mtime
        except Exception as e:
            self.target.log.debug("Could not determine last activity", exc_info=e)
            pass

        if last_seen == 0:
            return

        return from_unix(last_seen)

    @export(property=True)
    def install_date(self) -> Optional[datetime]:
        """Returns the install date of the system.

        The value of the registry key is stored as a Unix epoch timestamp.

        References:
            - https://winreg-kb.readthedocs.io/en/latest/_modules/winregrc/sysinfo.html?highlight=_ParseInstallDate
            - https://www.forensics-matters.com/2018/09/15/find-out-windows-installation-date/
        """

        key = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

        try:
            return from_unix(self.target.registry.key(key).value("InstallDate").value)
        except RegistryError:
            return

    @export(record=AppInitRecord)
    def appinit(self):
        """Return all available Application Initial (AppInit) DLLs registry key values.

        AppInit_DLLs is a mechanism that allows an arbitrary list of DLLs to be loaded into each user mode process on
        the system. It can be used as a persistence mechanism and/or elevate privileges by executing malicious content
        triggered by AppInit DLLs loaded into processes. DLLs that are specified in the AppInit_DLLs value in the
        Registry keys HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows or
        HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows are loaded by
        user32.dll into every process that loads user32.dll.

        References:
            - https://attack.mitre.org/techniques/T1546/010/
            - https://docs.microsoft.com/en-us/windows/win32/win7appqual/appinit-dlls-in-windows-7-and-windows-server-2008-r2?redirectedfrom=MSDN
            - https://docs.microsoft.com/en-US/windows/win32/dlls/secure-boot-and-appinit-dlls
        """  # noqa: E501
        keys = [
            (
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                "AppInit_DLLs",
            ),
            (
                "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                "AppInit_DLLs",
            ),
            ("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "AppInit_DLLs"),
            (
                "HKEY_CURRENT_USER\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                "AppInit_DLLs",
            ),
        ]

        for key, name in keys:
            for r in self.target.registry.keys(key):
                user = self.target.registry.get_user(r)
                try:
                    value = r.value(name)
                    path = uri.from_windows(value.value)
                    yield AppInitRecord(
                        ts=r.ts,
                        path=path,
                        _target=self.target,
                        _user=user,
                        _key=r,
                    )
                except RegistryError:
                    continue

    @export(record=KnownDllRecord)
    def knowndlls(self):
        """Return all available KnownDLLs registry key values.

        The KnownDLLs registry key values are used to cache frequently used system DLLs. Initially, it was added to
        accelerate application loading, but also it can be considered as a security mechanism, as it prevents malware
        from putting Trojan versions of system DLLs to the application folders (as all main DLLs belong to KnownDLLs,
        the version from the application folder will be ignored). However, these registry keys can still be leveraged
        to perform DLL injection.

        References:
            - https://www.apriorit.com/dev-blog/257-dll-injection
        """
        key = "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\KnownDlls"

        try:
            for r in self.target.registry.keys(key):
                user = self.target.registry.get_user(r)
                for value in r.values():
                    path = uri.from_windows(value.value)
                    yield KnownDllRecord(
                        ts=r.ts,
                        path=path,
                        _target=self.target,
                        _user=user,
                        _key=r,
                    )
        except RegistryError:
            pass

    @export(record=SessionManagerRecord)
    def sessionmanager(self):
        """Return interesting Session Manager (Smss.exe) registry key entries.

        Session Manager (Smss.exe) is the first user-mode process started by the kernel and performs several tasks,
        such as creating environment variables, starts the Windows Logon Manager (winlogon.exe), etc. The BootExecute
        registry key holds the Windows tasks that cannot be performed when Windows is running, the Execute registry key
        should never be populated when Windows is installed. Can be leveraged as persistence mechanisms.

        References:
            - https://en.wikipedia.org/wiki/Session_Manager_Subsystem
            - https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2
        """
        keys = [
            ("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager", "BootExecute"),
            ("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager", "Execute"),
            ("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\SubSystems", "windows"),
            ("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\WOW", "cmdline"),
            ("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\WOW", "wowcmdline"),
        ]

        for key, name in keys:
            for r in self.target.registry.keys(key):
                try:
                    value = r.value(name)
                    data = value.value
                except RegistryError:
                    continue

                user = self.target.registry.get_user(r)

                if isinstance(data, list):
                    for d in data:
                        if d == "autocheck autochk *":
                            continue

                        path = uri.from_windows(d)
                        yield SessionManagerRecord(
                            ts=r.ts,
                            path=path,
                            _target=self.target,
                            _user=user,
                            _key=r,
                        )
                else:
                    path = uri.from_windows(data.split(" ")[0])
                    yield SessionManagerRecord(
                        ts=r.ts,
                        path=path,
                        _target=self.target,
                        _user=user,
                        _key=r,
                    )

    @export(record=NullSessionPipeRecord)
    def nullsessionpipes(self):
        """Return the NullSessionPipes registry key value.

        The NullSessionPipes registry key value specifies server pipes and shared folders that are excluded from the
        policy that does not allow null session access. A null session implies that access to a network resource, most
        commonly the IPC$ "Windows Named Pipe" share, was granted without authentication. Also known as anonymous or
        guest access. These can thus be accessed without authentication and can be leveraged for latteral movement
        and/or privilege escalation.

        References:
            - https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares
        """  # noqa: E501
        key = "HKLM\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters"
        for r in self.target.registry.keys(key):
            user = self.target.registry.get_user(r)
            try:
                value = r.value("NullSessionPipes")
                for pipe in value.value:
                    yield NullSessionPipeRecord(
                        name=pipe,
                        _target=self.target,
                        _user=user,
                        _key=r,
                    )
            except RegistryError:
                continue

    @export(record=NdisRecord)
    def ndis(self):
        """Return network registry key entries."""
        key = "HKLM\\System\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
        for r in self.target.registry.keys(key):
            user = self.target.registry.get_user(r)
            for sub in r.subkeys():
                for network in sub.subkeys():
                    if network.name == "Descriptions":
                        continue

                    name = None
                    pnpinstanceid = None

                    try:
                        name = network.value("Name").value
                    except RegistryError:
                        pass

                    try:
                        pnpinstanceid = network.value("PnpInstanceID").value
                    except RegistryError:
                        pass

                    yield NdisRecord(
                        ts=network.ts,
                        network=sub.name,
                        name=name,
                        pnpinstanceid=pnpinstanceid,
                        _target=self.target,
                        _user=user,
                        _key=network,
                    )

    @export(record=CommandProcAutoRunRecord)
    def commandprocautorun(self):
        """Return all available Command Processor (cmd.exe) AutoRun registry key values.

        The Command Processor AutoRun registry key values contain commands that are run each time the Command Processor
        (cmd.exe) is started. Since these commands are not shown to the user in the Command Processor, it can be
        exploited by an adversary to hide malicious commands or leverage as a persistence mechanism

        References:
            - https://devblogs.microsoft.com/oldnewthing/20071121-00/?p=24433
            - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc779439%28v=ws.10%29?redirectedfrom=MSDN
        """  # noqa: E501
        keys = [
            ("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Command Processor", "AutoRun"),
            ("HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Command Processor", "AutoRun"),
            ("HKEY_CURRENT_USER\\Software\\Microsoft\\Command Processor", "AutoRun"),
            ("HKEY_CURRENT_USER\\Software\\Wow6432Node\\Microsoft\\Command Processor", "AutoRun"),
        ]

        for key, name in keys:
            for r in self.target.registry.keys(key):
                user = self.target.registry.get_user(r)
                try:
                    value = r.value(name)
                    path = uri.from_windows(value.value)
                    yield CommandProcAutoRunRecord(
                        ts=r.ts,
                        path=path,
                        _target=self.target,
                        _user=user,
                        _key=r,
                    )
                except RegistryError:
                    continue

    @export(record=AlternateShellRecord)
    def alternateshell(self):
        """Return the AlternateShell registry key value.

        The AlternateShell registry key, HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Safeboot, specifies the
        shell that is used when a Windows system is started in "Safe Mode with Command Prompt". Can be leveraged as a
        persistence mechanism.

        References:
            - https://technet.microsoft.com/en-us/library/cc976124.aspx
        """
        key = "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Safeboot"

        for r in self.target.registry.keys(key):
            user = self.target.registry.get_user(r)
            value = r.value("AlternateShell")
            path = uri.from_windows(value.value)
            yield AlternateShellRecord(
                ts=r.ts,
                path=path,
                _target=self.target,
                _user=user,
                _key=r,
            )

    @export(record=BootShellRecord)
    def bootshell(self):
        """Return the BootShell registry key entry.

        Usually contains a path to bootim.exe which is Windows's recovery menu.
        This registry key can be used as a persistence mechanism.
        """
        key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"

        for r in self.target.registry.keys(key):
            user = self.target.registry.get_user(r)
            try:
                value = r.value("BootShell")
            except RegistryError:
                continue

            path = uri.from_windows(value.value)
            yield BootShellRecord(
                ts=r.ts,
                path=path,
                _target=self.target,
                _user=user,
                _key=r,
            )

    @export(record=FileRenameOperationRecord)
    def filerenameop(self):
        """Return all pending file rename operations.

        The PendingFileRenameOperations registry key value contains information about files that will be renamed on
        reboot. Can be used to hunt for malicious binaries.

        References:
            - https://forensicatorj.wordpress.com/2014/06/25/interpreting-the-pendingfilerenameoperations-registry-key-for-forensics/
            - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc960241%28v=technet.10%29?redirectedfrom=MSDN
            - https://qtechbabble.wordpress.com/2020/06/26/use-pendingfilerenameoperations-registry-key-to-automatically-delete-a-file-on-reboot/
        """  # noqa: E501
        key = "HKLM\\System\\CurrentControlSet\\Control\\Session Manager"
        for r in self.target.registry.keys(key):
            user = self.target.registry.get_user(r)
            try:
                value = r.value("PendingFileRenameOperations")
                paths = map(uri.from_windows, value.value)
            except RegistryError:
                continue

            for path in paths:
                yield FileRenameOperationRecord(
                    ts=r.ts,
                    path=path,
                    _target=self.target,
                    _user=user,
                    _key=r,
                )

    @export(record=WinRarRecord)
    def winrar(self):
        """Return all available WinRAR history registry key values."""
        keys = [
            "HKEY_CURRENT_USER\\Software\\WinRAR\\ArcHistory",
            "HKEY_CURRENT_USER\\Software\\WinRAR\\DialogEditHistory\\ArcName",
            "HKEY_CURRENT_USER\\Software\\WinRAR\\DialogEditHistory\\ExtrPath",
        ]

        for key in keys:
            for r in self.target.registry.keys(key):
                user = self.target.registry.get_user(r)
                for v in r.values():
                    path = uri.from_windows(v.value)
                    yield WinRarRecord(
                        ts=r.ts,
                        path=path,
                        _target=self.target,
                        _user=user,
                        _key=r,
                    )

    @export(record=WinSockNamespaceProviderRecord)
    def winsocknamespaceprovider(self):
        """Return available protocols stored in the Winsock catalog database.

        References:
            - https://docs.microsoft.com/en-us/windows/win32/winsock/name-space-service-providers-2?redirectedfrom=MSDN
        """
        keys = [
            "HKLM\\System\\CurrentControlSet\\Services\\Winsock2\\Parameters\\namespace_catalog5\\catalog_entries",
            "HKLM\\System\\CurrentControlSet\\Services\\Winsock2\\Parameters\\namespace_catalog5\\catalog_entries64",
        ]

        for key in keys:
            for r in self.target.registry.keys(key):
                user = self.target.registry.get_user(r)
                for s in r.subkeys():
                    yield WinSockNamespaceProviderRecord(
                        ts=r.ts,
                        librarypath=s.value("LibraryPath").value,
                        displaystring=s.value("DisplayString").value,
                        providerid=s.value("ProviderID").value,
                        enabled=s.value("Enabled").value,
                        version=s.value("Version").value,
                        _target=self.target,
                        _user=user,
                        _key=s,
                    )

    @export(property=True)
    def codepage(self) -> Optional[str]:
        """Returns the current active codepage on the system."""

        key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage"

        try:
            return self.target.registry.key(key).value("ACP").value
        except RegistryError:
            pass
