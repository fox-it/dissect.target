from __future__ import annotations

import logging
import re
import uuid
from struct import unpack
from typing import Iterator, Optional, Tuple, Union

from dissect.target.filesystem import Filesystem
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugin import OperatingSystem, OSPlugin, arg, export
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
    @arg("--sessions", action="store_true", help="Parse syslog for recent user sessions")
    def users(self, sessions: bool = False) -> Iterator[UnixUserRecord]:
        """Recover users from /etc/passwd, /etc/master.passwd or /var/log/syslog session logins."""

        seen_users = set()

        # Yield users found in passwd files.
        for passwd_file in ["/etc/passwd", "/etc/master.passwd"]:
            if (path := self.target.fs.path(passwd_file)).exists():
                for line in path.open("rt"):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    pwent = dict(enumerate(line.split(":")))
                    seen_users.add((pwent.get(0), pwent.get(5), pwent.get(6)))
                    yield UnixUserRecord(
                        name=pwent.get(0),
                        passwd=pwent.get(1),
                        uid=pwent.get(2),
                        gid=pwent.get(3),
                        gecos=pwent.get(4),
                        home=pwent.get(5),
                        shell=pwent.get(6),
                        source=passwd_file,
                        _target=self.target,
                    )

        # Find users not in passwd files by parsing recent
        # syslog ldap, kerberos and x-session logins.
        # Must be enabled using the --sessions flag
        if sessions and (path := self.target.fs.path("/var/log/syslog")).exists():
            sessions = []
            cur_session = -1
            needles = {
                ("setting HOME=", "home"),
                ("setting SHELL=", "shell"),
                ("setting USER=", "name"),
            }

            for line in path.open("rt"):
                # Detect the beginning of a new session activation in the syslog
                #
                # dbus-update-activation-environment starts a new session with
                # DBUS_SESSION_BUS_ADDRESS, XDG_RUNTIME_DIR and/or DISPLAY
                # Using DBUS_SESSION_BUS_ADDRESS seems to work fine for now.
                if "setting DBUS_SESSION_BUS_ADDRESS=" in line:
                    bus = line.split("DBUS_SESSION_BUS_ADDRESS=")[1].strip()
                    cur_session += 1
                    sessions.append({"bus": bus, "name": None, "home": None, "shell": None, "uid": None})

                # Search the following lines for more information on the previousley detected session.
                for n, k in needles:
                    if n in line and "dbus-update-activation-environment" in line:
                        sessions[cur_session][k] = line.split(n)[1].strip()

            for user in sessions:
                # Only return users we didn't already find in previously parsed passwd files and past sessions.
                current_user = (user["name"], user["home"], user["shell"])
                if current_user in seen_users:
                    continue

                seen_users.add(current_user)

                yield UnixUserRecord(
                    name=user["name"],
                    home=user["home"],
                    shell=user["shell"],
                    source="/var/log/syslog",
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
