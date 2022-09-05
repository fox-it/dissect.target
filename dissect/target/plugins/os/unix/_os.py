from __future__ import annotations

import logging
import re
import uuid
from struct import unpack
from typing import Iterator, Optional, Tuple, Union

from dissect.target.filesystem import Filesystem
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugin import OSPlugin, OperatingSystem, export
from dissect.target.target import Target

log = logging.getLogger(__name__)


class UnixPlugin(OSPlugin):
    def __init__(self, target: Target):
        super().__init__(target)
        self._add_mounts()
        self._hostname_dict = self._parse_hostname_string()
        self._hosts_dict = self._parse_hosts_string()
        self._os_release = self._parse_os_release()

    @classmethod
    def detect(cls, target: Target) -> Optional[Filesystem]:
        for fs in target.filesystems:
            if fs.exists("/var") and fs.exists("/etc"):
                return fs

        return None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> UnixPlugin:
        target.fs.mount("/", sysvol)
        return cls(target)

    @export(record=UnixUserRecord)
    def users(self) -> Iterator[UnixUserRecord]:
        passwd = self.target.fs.path("/etc/passwd")
        if not passwd.exists():
            return

        for line in passwd.open("rt"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            pwent = line.split(":")
            yield UnixUserRecord(
                name=pwent[0],
                passwd=pwent[1],
                uid=pwent[2],
                gid=pwent[3],
                gecos=pwent[4],
                home=pwent[5],
                shell=pwent[6],
                _target=self.target,
            )

    @export(property=True)
    def architecture(self) -> str:
        return self._get_architecture(self.os)

    @export(property=True)
    def hostname(self) -> Optional[str]:
        hosts_string = self._hosts_dict.get("hostname", "localhost")
        return self._hostname_dict.get("hostname", hosts_string)

    @export(property=True)
    def domain(self) -> Optional[str]:
        domain = self._hostname_dict.get("domain", "localhost")
        if domain == "localhost":
            domain = self._hosts_dict["hostname", "localhost"]
            if domain == self.hostname:
                return domain  # domain likely not defined, so localhost is the domain.
        return domain

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.UNIX.value

    def _parse_hostname_string(self, paths: Optional[list[str]] = None) -> Optional[dict[str, str]]:
        """
        Returns a dict with containing the hostname and domain name portion of the path(s) specified

        Args:
            paths (list): list of paths
        """
        paths = paths or ["/etc/hostname", "/etc/HOSTNAME"]
        hostname_string = None

        for path in paths:
            for fs in self.target.filesystems:
                if fs.exists(path):
                    hostname_string = fs.path(path).open("rt").read().rstrip()

            if hostname_string and "." in hostname_string:
                hostname_string = hostname_string.split(".", maxsplit=1)
                hostname_dict = {"hostname": hostname_string[0], "domain": hostname_string[1]}
            else:
                hostname_dict = {"hostname": hostname_string, "domain": None}

            return hostname_dict

    def _parse_hosts_string(self, paths: Optional[list[str]] = None) -> dict[str, str]:
        paths = paths or ["/etc/hosts"]
        hosts_string = {"ip": None, "hostname": None}

        for path in paths:
            for fs in self.target.filesystems:
                if fs.exists(path):
                    for line in fs.path(path).open("rt").readlines():
                        line = line.split()
                        if not line:
                            continue

                        if (line[0].startswith("127.0.") or line[0].startswith("::1")) and line[
                            1
                        ].lower() != "localhost":
                            hosts_string = {"ip": line[0], "hostname": line[1]}
        return hosts_string

    def _add_mounts(self) -> None:
        fstab = self.target.fs.path("/etc/fstab")

        volumes_to_mount = [v for v in self.target.volumes if v.fs]

        for dev_id, volume_name, _, mount_point in parse_fstab(fstab, self.target.log):

            for volume in volumes_to_mount:
                fs_id = None
                last_mount = None

                if dev_id:
                    if volume.fs.__fstype__ == "xfs":
                        fs_id = volume.fs.xfs.uuid
                    elif volume.fs.__fstype__ == "extfs":
                        fs_id = volume.fs.extfs.uuid
                        last_mount = volume.fs.extfs.last_mount
                    elif volume.fs.__fstype__ == "fat":
                        fs_id = volume.fs.fatfs.volume_id

                if (
                    (fs_id and (fs_id == dev_id))
                    or (volume.name and (volume.name == volume_name))
                    or (last_mount and (last_mount == mount_point))
                ):
                    self.target.log.debug("Mounting %s at %s", volume, mount_point)
                    self.target.fs.mount(mount_point, volume.fs)

    def _parse_os_release(self, glob: Optional[str] = None) -> dict[str, str]:
        glob = glob or "/etc/*-release"

        os_release = {}

        for path in self.target.fs.glob(glob):
            if self.target.fs.path(path).exists():

                with self.target.fs.path(path).open("rt") as release_file:
                    for line in release_file:
                        if line.startswith("#"):
                            continue
                        try:
                            name, value = line.split("=", maxsplit=1)
                            os_release[name] = value.replace('"', "").replace("\n", "")
                        except ValueError:
                            continue
        return os_release

    def _get_architecture(self, os: str = "unix") -> Optional[str]:
        arch_strings = {
            0x00: "Unknown",
            0x02: "SPARC",
            0x03: "x86",
            0x08: "MIPS",
            0x14: "PowerPC",
            0x16: "S390",
            0x28: "ARM",
            0x2A: "SuperH",
            0x32: "IA-64",
            0x3E: "x86_64",
            0xB7: "AArch64",
            0xF3: "RISC-V",
        }

        for fs in self.target.filesystems:
            if fs.exists("/bin/ls"):
                fh = fs.open("/bin/ls")
                fh.seek(4)
                # ELF - e_ident[EI_CLASS]
                bits = unpack("B", fh.read(1))[0]
                fh.seek(18)
                # ELF - e_machine
                arch = unpack("H", fh.read(2))[0]
                arch = arch_strings.get(arch)

                if bits == 1:  # 32 bit system
                    return f"{arch}_32-{os}"
                else:
                    return f"{arch}-{os}"


def parse_fstab(
    fstab: TargetPath,
    log: logging.Logger = log,
) -> Iterator[Tuple[Union[uuid.UUID, str], str, str, str]]:
    """Parse fstab file and return a generator that streams the details of entries,
    with unsupported FS types and block devices filtered away.
    """

    SKIP_FS_TYPES = (
        "swap",
        "tmpfs",
        "devpts",
        "sysfs",
        "procfs",
        "overlayfs",
    )

    if not fstab.exists():
        return

    for entry in fstab.open("rt"):

        entry = entry.strip()
        if entry.startswith("#"):
            continue

        entry_parts = re.split(r"\s+", entry)

        if len(entry_parts) != 6:
            continue

        dev, mount_point, fs_type, _, _, _ = entry_parts

        if fs_type in SKIP_FS_TYPES:
            log.warning("Skipped FS type: %s, %s, %s", fs_type, dev, mount_point)
            continue

        dev_id = None
        volume_name = None
        if dev.startswith(("/dev/mapper", "/dev/gpt")):
            volume_name = dev.rsplit("/")[-1]
        elif dev.startswith("/dev/") and dev.count("/") == 3:
            volume_name = "-".join(dev.rsplit("/")[-2:])
        elif dev.startswith("UUID="):
            dev_id = dev.split("=")[1]
            try:
                dev_id = uuid.UUID(dev_id)
            except ValueError:
                pass
        else:
            log.warning("Unsupported mount device: %s %s", dev, mount_point)
            continue

        if mount_point == "/":
            continue

        yield dev_id, volume_name, fs_type, mount_point
