from __future__ import annotations

import struct
from typing import Any, Iterator, Optional

from dissect.target.exceptions import RegistryError, RegistryValueNotFoundError
from dissect.target.filesystem import Filesystem
from dissect.target.helpers.record import WindowsUserRecord
from dissect.target.plugin import OperatingSystem, OSPlugin, export
from dissect.target.target import Target


class WindowsPlugin(OSPlugin):
    CURRENT_VERSION_KEY = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion"

    def __init__(self, target: Target):
        super().__init__(target)

        # Just run this here for now
        self.add_mounts()

    @classmethod
    def detect(cls, target: Target) -> Optional[Filesystem]:
        for fs in target.filesystems:
            if fs.exists("/windows/system32") or fs.exists("/winnt"):
                return fs

        return None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> WindowsPlugin:
        target.fs.case_sensitive = False
        target.fs.alt_separator = "\\"
        target.fs.mount("sysvol", sysvol)
        target.fs.mount("c:", sysvol)

        if not sysvol.exists("boot/BCD"):
            for fs in target.filesystems:
                if fs.exists("boot") and fs.exists("boot/BCD"):
                    target.fs.mount("efi", fs)

        if target.fs.exists("sysvol/windows"):
            target.windir = target.fs.get("sysvol/windows")
        else:
            target.windir = target.fs.get("sysvol/winnt")

        return cls(target)

    def add_mounts(self) -> None:
        self.target.props["mounts_added"] = True
        try:
            for key in self.target.registry.keys("HKLM\\System\\MountedDevices"):
                for entry in key.values():
                    name, value = entry.name, entry.value
                    if not name.lower().startswith("\\"):
                        continue

                    p = name.lower()[1:].split("\\")
                    if p[0] == "dosdevices":
                        drive = p[1]
                        if drive == "c:":
                            continue

                        if value.startswith(b"DMIO:ID:"):
                            guid = value[8:]

                            for volume in self.target.volumes:
                                if volume.guid == guid:
                                    self.target.fs.mount(drive, volume.fs)

                        elif len(value) == 12:
                            serial, offset = struct.unpack("<IQ", value)
                            for disk in self.target.disks:
                                if disk.vs and disk.vs.serial == serial:
                                    for volume in disk.vs.volumes:
                                        if volume.offset == offset and volume.fs:
                                            self.target.fs.mount(drive, volume.fs)
                                            break
        except Exception as e:
            self.target.log.warning("Failed to map drive letters", exc_info=e)

    @export(property=True)
    def hostname(self) -> Optional[str]:
        key = "HKLM\\SYSTEM\\ControlSet001\\Control\\Computername\\Computername"
        try:
            return self.target.registry.value(key, "Computername").value
        except RegistryError:
            return None

    @export(property=True)
    def ips(self) -> list[str]:
        key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"
        fields = ["IPAddress", "DhcpIPAddress"]
        ips = set()

        for r in self.target.registry.keys(key):
            for s in r.subkeys():
                for field in fields:
                    try:
                        ip = s.value(field).value
                    except RegistryValueNotFoundError:
                        continue

                    if isinstance(ip, str):
                        ip = [ip]

                    for i in ip:
                        if i == "0.0.0.0":
                            continue

                        ips.add(i)

        return list(ips)

    def _get_version_reg_value(self, value_name: str) -> Any:
        try:
            value = self.target.registry.value(self.CURRENT_VERSION_KEY, value_name).value
        except RegistryError:
            value = None

        return value

    def _legacy_current_version(self) -> Optional[str]:
        """Returns the NT version as used up to and including NT 6.3.

        This corresponds with Windows 8 / Windows 2012 Server.

        Returns:
            The string value of the NT version number or ``None`` if the
            CurrentVersion sub key is not present or any other registry error
            occurred.
        """
        return self._get_version_reg_value("CurrentVersion")

    def _major_version(self) -> Optional[int]:
        """Return the NT major version number (starting from NT 10.0 / Windows 10).

        Returns:
            The integer value of the NT major version number or ``None`` if the
            CurrentMajorVersionNumber sub key is not present or any other
            registry error occurred.
        """
        return self._get_version_reg_value("CurrentMajorVersionNumber")

    def _minor_version(self) -> Optional[int]:
        """Return the NT minor version number (starting from NT 10.0 / Windows 10).

        Returns:
            The integer value of the NT minor version number or ``None`` if the
            CurrentMinorVersionNumber sub key is not present or any other
            registry error occurred.
        """
        return self._get_version_reg_value("CurrentMinorVersionNumber")

    def _nt_version(self) -> Optional[int]:
        """Return the Windows NT version in x.y format.

        For systems up to and including NT 6.3 (Win 8 / Win 2012 Server) this
        will be the value of the CurrentVersion sub key.

        For systems starting from NT 10.0 (Win 10) this will be a value
        constructed from the combination of the CurrentMajorVersionNumber and
        CurrentMinorVersionNumber sub keys.

        Returns:
            The string value of the NT version or ``None`` if the any of the
            sub keys are not present or any other registry error occurred.
        """
        version = None

        major_version = self._major_version()
        if major_version is not None:
            minor_version = self._minor_version()
            if minor_version is None:
                minor_version = ""
            version = f"{major_version}.{minor_version}"
        else:
            version = self._legacy_current_version()

        return version

    @export(property=True)
    def version(self) -> Optional[str]:
        """Return a string representation of the Windows version of the target.

        For Windows versions before Windows 10 this looks like::

            <ProductName> (NT <CurrentVersion>) <CurrentBuildNumber>.<UBR> <CSDVersion>

        For Windows versions since Windows 10 this looks like::

            <ProductName> (NT <CurrentMajorVersionNumber>.<CurrentMinorVersionNumber>) <CurrentBuildNumber>.<UBR> <CSDVersion>

        Where the registry values used are between ``<...>``.

        Note that the ``<UBR>`` and ``<CSDVersion>`` may or may not be available,
        depending on whether updates and service packs are installed.

        Note also that we don't show the "version" (aka FeatureRelease) as
        shown by WinVer.exe, which uses the registry values:

        ``<ReleaseId>``: Windows up to Windows 10 ReleaseId <= 2004

        ``<DisplayVersion>``: from Windows 10 ReleaseId >= 2009
                              (DisplayVersion = 20H2 in this case)

        Returns:
            If any one of the registry values used in the version string can be
            found in the registry, a string is returned as described above.
            All values that can not be found and should be present are replaced
            with ``<UNKNOWN value_name>``.
            If none of the values can be found, ``None`` is returned.
        """  # noqa: E501
        # https://www.vcloudinfo.com/2020/12/how-to-decode-windows-version-numbers.html

        def _part_str(parts: dict[str, Any], name: str) -> str:
            value = parts.get(name)
            if value is None:
                value = f"<Unknown {name}>"
            else:
                value = str(value)

            return value

        version_parts = {}
        version_parts["ProductName"] = self._get_version_reg_value("ProductName")
        version_parts["CurrentVersion"] = self._nt_version()
        # Note that the CurrentBuild key value also exists, often with the
        # same value, but is apparently deprecated.
        version_parts["CurrentBuildNumber"] = self._get_version_reg_value("CurrentBuildNumber")
        # Update Build Revision (seems to be present from NT 6.1 onwards).
        version_parts["UBR"] = self._get_version_reg_value("UBR")
        # Service Pack Version, when installed using the normal method (may not be present).
        version_parts["CSDVersion"] = self._get_version_reg_value("CSDVersion")

        version_string = None
        if any(map(lambda value: value is not None, version_parts.values())):
            version = []

            prodcut_name = _part_str(version_parts, "ProductName")
            version.append(prodcut_name)

            nt_version = _part_str(version_parts, "CurrentVersion")
            version.append(f"(NT {nt_version})")

            build_version = _part_str(version_parts, "CurrentBuildNumber")
            ubr = version_parts["UBR"]
            if ubr:
                build_version = f"{build_version}.{ubr}"
            version.append(build_version)

            csd_version = version_parts["CSDVersion"]
            if csd_version is not None:
                version.append(f"{csd_version}")

            version_string = " ".join(version)

        return version_string

    @export(property=True)
    def architecture(self) -> Optional[str]:
        """
        Returns a dict containing the architecture and bitness of the system

        Returns:
            Dict: arch: architecture, bitness: bits
        """

        arch_strings = {
            "x86": 32,
            "IA64": 64,
            "ARM64": 64,
            "EM64T": 64,
            "AMD64": 64,
        }

        key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"

        try:
            arch = self.target.registry.key(key).value("PROCESSOR_ARCHITECTURE").value
            bits = arch_strings.get(arch)

            # return {"arch": arch, "bitness": bits}
            if bits == 64:
                return f"{arch}-win{bits}".lower()
            else:
                return f"{arch}_{bits}-win{bits}".lower()
        except RegistryError:
            pass

    @export(record=WindowsUserRecord)
    def users(self) -> Iterator[WindowsUserRecord]:
        key = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
        sids = set()
        for k in self.target.registry.keys(key):
            for subkey in k.subkeys():
                sid = subkey.name
                if sid in sids:
                    continue

                sids.add(sid)
                name = None
                home = None
                try:
                    profile_image_path = subkey.value("ProfileImagePath")
                except RegistryValueNotFoundError:
                    pass
                else:
                    home = profile_image_path.value
                    name = home.split("\\")[-1]

                yield WindowsUserRecord(
                    sid=subkey.name,
                    name=name,
                    home=home,
                    _target=self.target,
                )

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.WINDOWS.value
