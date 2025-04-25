from __future__ import annotations

import operator
import struct
from typing import TYPE_CHECKING, Any

from dissect.target.exceptions import RegistryError, RegistryValueNotFoundError
from dissect.target.helpers.record import WindowsUserRecord
from dissect.target.plugin import OperatingSystem, OSPlugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target

ARCH_MAP = {
    "x86": 32,
    "IA64": 64,
    "ARM64": 64,
    "EM64T": 64,
    "AMD64": 64,
}


class WindowsPlugin(OSPlugin):
    CURRENT_VERSION_KEY = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion"

    def __init__(self, target: Target):
        super().__init__(target)

        # Just run this here for now
        self.add_mounts()

        target.props["sysvol_drive"] = next(
            (mnt for mnt, fs in target.fs.mounts.items() if fs is target.fs.mounts.get("sysvol") and mnt != "sysvol"),
            None,
        )

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        for fs in target.filesystems:
            if fs.exists("/windows/system32") or fs.exists("/winnt"):
                return fs

        return None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> Self:
        target.fs.case_sensitive = False
        target.fs.alt_separator = "\\"
        target.fs.mount("sysvol", sysvol)

        if not sysvol.exists("boot/BCD"):
            for fs in target.filesystems:
                if fs.exists("boot/BCD") or fs.exists("EFI/Microsoft/Boot/BCD"):
                    target.fs.mount("efi", fs)

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

                        if value.startswith(b"DMIO:ID:"):
                            guid = value[8:]

                            for volume in self.target.volumes:
                                if volume.guid == guid and volume.fs:
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
            self.target.log.warning("Failed to map drive letters")
            self.target.log.debug("", exc_info=e)

        sysvol_drive = self.target.fs.mounts.get("sysvol")
        if not sysvol_drive:
            self.target.log.warning("No sysvol drive found")
        elif operator.countOf(self.target.fs.mounts.values(), sysvol_drive) == 1:
            # Fallback mount the sysvol to C: if we didn't manage to mount it to any other drive letter
            if "c:" not in self.target.fs.mounts:
                self.target.log.debug("Unable to determine drive letter of sysvol, falling back to C:")
                self.target.fs.mount("c:", sysvol_drive)
            else:
                self.target.log.warning("Unknown drive letter for sysvol")

    @export(property=True)
    def hostname(self) -> str | None:
        key = "HKLM\\SYSTEM\\ControlSet001\\Control\\Computername\\Computername"
        try:
            return self.target.registry.value(key, "Computername").value
        except RegistryError:
            return None

    @export(property=True)
    def ips(self) -> list[str]:
        return list(set(map(str, self.target.network.ips())))

    def _get_version_reg_value(self, value_name: str) -> Any:
        try:
            value = self.target.registry.value(self.CURRENT_VERSION_KEY, value_name).value
        except RegistryError:
            value = None

        return value

    def _legacy_current_version(self) -> str | None:
        """Returns the NT version as used up to and including NT 6.3.

        This corresponds with Windows 8 / Windows 2012 Server.

        Returns:
            The string value of the NT version number or ``None`` if the
            CurrentVersion sub key is not present or any other registry error
            occurred.
        """
        return self._get_version_reg_value("CurrentVersion")

    def _major_version(self) -> int | None:
        """Return the NT major version number (starting from NT 10.0 / Windows 10).

        Returns:
            The integer value of the NT major version number or ``None`` if the
            CurrentMajorVersionNumber sub key is not present or any other
            registry error occurred.
        """
        return self._get_version_reg_value("CurrentMajorVersionNumber")

    def _minor_version(self) -> int | None:
        """Return the NT minor version number (starting from NT 10.0 / Windows 10).

        Returns:
            The integer value of the NT minor version number or ``None`` if the
            CurrentMinorVersionNumber sub key is not present or any other
            registry error occurred.
        """
        return self._get_version_reg_value("CurrentMinorVersionNumber")

    def _nt_version(self) -> int | None:
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
    def version(self) -> str | None:
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
            return f"<Unknown {name}>" if value is None else str(value)

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
        if any(value is not None for value in version_parts.values()):
            version = []

            nt_version = _part_str(version_parts, "CurrentVersion")
            build_version = _part_str(version_parts, "CurrentBuildNumber")
            prodcut_name = _part_str(version_parts, "ProductName")

            # CurrentBuildNumber >= 22000 on NT 10.0 indicates Windows 11.
            # https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information
            try:
                if nt_version == "10.0" and int(build_version) >= 22_000:
                    prodcut_name = prodcut_name.replace("Windows 10", "Windows 11")
            except ValueError:
                pass

            version.append(prodcut_name)
            version.append(f"(NT {nt_version})")

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
    def architecture(self) -> str | None:
        """Returns a target triple containing the architecture and bitness of the system.

        Returns:
            Target triple string.
        """

        key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"

        try:
            arch = self.target.registry.key(key).value("PROCESSOR_ARCHITECTURE").value
            bits = ARCH_MAP.get(arch)

            if bits == 64:
                return f"{arch}-win{bits}".lower()
            return f"{arch}_{bits}-win{bits}".lower()
        except RegistryError:
            pass

    @export(record=WindowsUserRecord)
    def users(self) -> Iterator[WindowsUserRecord]:
        # Be aware that this function can never do anything which needs user
        # registry hives. Initializing those hives will need this function,
        # which will then cause a recursion.
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
                    home=self.target.resolve(home),
                    _target=self.target,
                )

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.WINDOWS.value
