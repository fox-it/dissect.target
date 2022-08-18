from __future__ import annotations

import struct
from typing import Iterator, Optional

from dissect.target.exceptions import RegistryError, RegistryValueNotFoundError
from dissect.target.filesystem import Filesystem
from dissect.target.helpers.record import WindowsUserRecord
from dissect.target.plugin import OSPlugin, export, OperatingSystem
from dissect.target.target import Target


class WindowsPlugin(OSPlugin):
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

    @export(property=True)
    def version(self) -> Optional[str]:
        key = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion"
        csd_version = str()

        try:
            csd_version = self.target.registry.key(key).value("CSDVersion").value
        except RegistryError:
            pass

        try:
            r = self.target.registry.key(key)
            product_name = r.value("ProductName").value
            current_version = r.value("CurrentVersion").value
            current_build_number = r.value("CurrentBuildNumber").value
            return f"{product_name} (NT {current_version}) {current_build_number} {csd_version}"
        except RegistryError:
            pass

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

    @export(property=True)
    def codepage(self) -> Optional[str]:
        """Returns the current active codepage on the system."""

        key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage"

        try:
            return self.target.registry.key(key).value("ACP").value
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
