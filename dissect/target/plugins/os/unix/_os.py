from __future__ import annotations

import logging
import re
import uuid
from typing import TYPE_CHECKING, Callable

from flow.record.fieldtypes import posix_path

from dissect.target.exceptions import FilesystemError
from dissect.target.filesystems.nfs import NfsFilesystem
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.nfs.client.nfs import Client as NfsClient
from dissect.target.helpers.nfs.client.nfs import NfsError
from dissect.target.helpers.nfs.nfs3 import FileHandle, NfsStat
from dissect.target.helpers.record import UnixUserRecord
from dissect.target.helpers.sunrpc.client import LocalPortPolicy, auth_unix
from dissect.target.helpers.utils import parse_options_string
from dissect.target.loaders.local import LocalLoader
from dissect.target.plugin import OperatingSystem, OSPlugin, arg, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target

log = logging.getLogger(__name__)


# https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#ISA
ARCH_MAP = {
    0x00: "unknown",
    0x02: "sparc",
    0x03: "x86",
    0x08: "mips",
    0x14: "powerpc32",
    0x15: "powerpc64",
    0x16: "s390",  # and s390x
    0x28: "aarch32",  # armv7
    0x2A: "superh",
    0x32: "ia-64",
    0x3E: "x86_64",
    0xB7: "aarch64",  # armv8
    0xF3: "riscv64",
    0xF7: "bpf",
}


class UnixPlugin(OSPlugin):
    """UNIX plugin."""

    # Files to parse for user details
    PASSWD_FILES = ("/etc/passwd", "/etc/passwd-", "/etc/master.passwd")

    def __init__(self, target: Target):
        super().__init__(target)
        self._add_mounts()
        self._add_devices()
        self._hostname, self._domain = self._parse_hostname_string()
        self._hosts_dict = self._parse_hosts_string()
        self._os_release = self._parse_os_release()

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        # If the ``/var`` and ``/etc`` folders exist on a filesystem it is treated as a Unix-like filesystem
        for fs in target.filesystems:
            if fs.exists("/var") and fs.exists("/etc"):
                return fs

        return None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> Self:
        target.fs.mount("/", sysvol)
        return cls(target)

    @export(record=UnixUserRecord)
    @arg("--sessions", action="store_true", help="Parse syslog for recent user sessions")
    def users(self, sessions: bool = False) -> Iterator[UnixUserRecord]:
        """Yield unix user records from passwd files or syslog session logins.

        Resources:
            - https://manpages.ubuntu.com/manpages/oracular/en/man5/passwd.5.html
        """

        seen_users = set()

        # Yield users found in passwd files.
        for passwd_file in self.PASSWD_FILES:
            if (path := self.target.fs.path(passwd_file)).exists():
                for line in path.open("rt", errors="surrogateescape"):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    pwent = dict(enumerate(line.split(":")))

                    current_user = (pwent.get(0), pwent.get(5), pwent.get(6))
                    if current_user in seen_users:
                        continue
                    seen_users.add(current_user)
                    yield UnixUserRecord(
                        name=pwent.get(0),
                        passwd=pwent.get(1),
                        uid=pwent.get(2) or None,
                        gid=pwent.get(3) or None,
                        gecos=pwent.get(4),
                        home=posix_path(pwent.get(5)),
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
                    home=posix_path(user["home"]),
                    shell=user["shell"],
                    source="/var/log/syslog",
                    _target=self.target,
                )

    @export(property=True)
    def architecture(self) -> str | None:
        return self._get_architecture(self.os)

    @export(property=True)
    def hostname(self) -> str | None:
        return self._hostname or self._hosts_dict.get("hostname", "localhost")

    @export(property=True)
    def domain(self) -> str | None:
        if self._domain and "localhost" not in self._domain:
            return self._domain

        # fall back to /etc/hosts file
        if "localhost" not in (domain := self._hosts_dict.get("hostname", "")):
            return domain or None

        return None

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.UNIX.value

    def _parse_hostname_string(
        self, paths: list[tuple[str, Callable[[Path], str] | None]] | None = None
    ) -> tuple[str | None, str | None]:
        """Returns a tuple containing respectively the hostname and domain name portion of the path(s) specified.

        Args:
            paths (list): list of tuples with paths and callables to parse the path or None

        Returns:
            Tuple with hostname and domain strings.
        """
        hostname = None
        domain = None

        paths = paths or [
            ("/etc/hostname", None),
            ("/etc/HOSTNAME", None),
            ("/proc/sys/kernel/hostname", None),
            ("/etc/sysconfig/network", self._parse_rh_legacy),
            ("/etc/hosts", self._parse_etc_hosts),  # fallback if no other hostnames are found
        ]

        for path, callable in paths:
            if not (path := self.target.fs.path(path)).exists():
                continue

            hostname = callable(path) if callable else path.open("rt").read().rstrip()

            if hostname and "." in hostname:
                hostname, domain = hostname.split(".", maxsplit=1)

            break  # break whenever a valid hostname is found

        # Can be an empty string due to splitting of hostname and domain
        return hostname or None, domain or None

    def _parse_rh_legacy(self, path: Path) -> str | None:
        hostname = None
        file_contents = path.open("rt").readlines()
        for line in file_contents:
            if not line.startswith("HOSTNAME"):
                continue
            _, _, hostname = line.rstrip().partition("=")
        return hostname

    def _parse_etc_hosts(self, path: Path) -> str | None:
        for line in path.open("rt"):
            if line.startswith(("127.0.0.1 ", "::1 ")) and "localhost" not in line:
                return line.split(" ")[1]
        return None

    def _parse_hosts_string(self, paths: list[str] | None = None) -> dict[str, str]:
        paths = paths or ["/etc/hosts"]
        hosts_string = {}

        for path in paths:
            for fs in self.target.filesystems:
                if fs.exists(path):
                    for line in fs.path(path).open("rt").readlines():
                        if not (line := line.split()):
                            continue
                        if line[0].startswith(("127.0.", "::1")):
                            hosts_string = {"ip": line[0], "hostname": line[1]}
        return hosts_string

    def _add_mounts(self) -> None:
        fstab = self.target.fs.path("/etc/fstab")

        for dev_id, volume_name, mount_point, fs_type, options in parse_fstab(fstab, self.target.log):
            # Mount nfs, but only when target has been mapped by the `LocalLoader`
            if fs_type == "nfs":
                self._add_nfs(dev_id, volume_name, mount_point)
                continue

            opts = parse_options_string(options)
            subvol = opts.get("subvol", None)
            subvolid = opts.get("subvolid", None)
            for fs in self.target.filesystems:
                fs_id = None
                fs_subvol = None
                fs_subvolid = None
                fs_last_mount = None
                fs_volume_name = None
                vol_volume_name = fs.volume.name if fs.volume and not isinstance(fs.volume, list) else None

                if fs.__type__ == "xfs":
                    fs_id = fs.xfs.uuid
                    fs_volume_name = fs.xfs.name
                elif fs.__type__ == "ext":
                    fs_id = fs.extfs.uuid
                    fs_last_mount = fs.extfs.last_mount
                    fs_volume_name = fs.extfs.volume_name
                elif fs.__type__ == "btrfs":
                    fs_id = fs.btrfs.uuid
                    fs_subvol = fs.subvolume.path
                    fs_subvolid = fs.subvolume.objectid
                elif fs.__type__ == "fat":
                    fs_id = fs.fatfs.volume_id
                    # This normalizes fs_id to comply with libblkid generated UUIDs
                    # This is needed because FAT filesystems don't have a real UUID,
                    # but instead a volume_id which is not case-sensitive
                    fs_id = fs_id[:4].upper() + "-" + fs_id[4:].upper()

                if (
                    (fs_id and (fs_id == dev_id and (subvol == fs_subvol or subvolid == fs_subvolid)))
                    or (fs_last_mount and (fs_last_mount == mount_point))
                    or (fs_volume_name and (fs_volume_name == volume_name))
                    or (vol_volume_name and (vol_volume_name == volume_name))
                ):
                    self.target.log.debug("Mounting %s (%s) at %s", fs, fs.volume, mount_point)
                    self.target.fs.mount(mount_point, fs)

    @property
    def _is_nfs_enabled(self) -> bool:
        return isinstance(self.target._loader, LocalLoader) and "enable-nfs" in self.target.path_query

    def _log_nfs_mount_disabled(self, address: str, exported_dir: str, mount_point: str) -> None:
        if isinstance(self.target._loader, LocalLoader):
            log.warning(
                "NFS mount %s:%s at %s is disabled. To enable, pass --enable-nfs to the local loader. Alternatively, add a query parameter to the target query string: local?enable-nfs",  # noqa: E501
                address,
                exported_dir,
                mount_point,
            )
        else:
            log.warning(
                "NFS mount %s:%s at %s is unavailable on a non-local target",
                address,
                exported_dir,
                mount_point,
            )

    def _add_nfs(self, address: str, exported_dir: str, mount_point: str) -> None:
        if not self._is_nfs_enabled:
            self._log_nfs_mount_disabled(address, exported_dir, mount_point)
            return

        # Try all users to see if we can access the share
        def auth_setter(nfs_client: NfsClient, filehandle: FileHandle, _: list[int]) -> None:
            users = list(self.users())
            if not users:
                self.target.log.debug(
                    "No users found, trying root for mounting NFS share %s:%s at %s", address, exported_dir, mount_point
                )
                users = [UnixUserRecord(uid=0, gid=0)]

            for user in users:
                if user.uid is None or user.gid is None:
                    continue
                auth = auth_unix("machine", user.uid, user.gid, [])
                nfs_client.rebind_auth(auth)
                try:
                    self.target.log.debug("Trying to read NFS share with uid %d and gid %d", user.uid, user.gid)
                    # Use a readdir to check if we have access.
                    # RdJ: Perhaps an ACCESS call (to be implemented) is better than READDIR
                    nfs_client.readdir(filehandle)
                except NfsError as e:
                    if e.nfsstat != NfsStat.ERR_ACCES:
                        self.target.log.warning("Reading NFS share gives %s", e.nfsstat)
                        nfs_client.close()
                        raise
                else:
                    # We have access
                    return

            self.target.log.debug("No user has access to NFS share %s:%s at %s", address, exported_dir, mount_point)
            raise FilesystemError(f"No user has access to NFS share {address}:{exported_dir} at {mount_point}")

        try:
            self.target.log.debug("Mounting NFS share %s at %s", exported_dir, mount_point)
            nfs = NfsFilesystem.connect(address, exported_dir, auth_setter, LocalPortPolicy.PRIVILEGED)
            self.target.fs.mount(mount_point, nfs)
        except Exception as e:
            self.target.log.warning("Failed to mount NFS share %s:%s at %s", address, exported_dir, mount_point)
            self.target.log.debug("", exc_info=e)

    def _add_devices(self) -> None:
        """Add some virtual block devices to the target.

        Currently only adds LVM devices.
        """
        vfs = self.target.fs.append_layer()

        for volume in self.target.volumes:
            if volume.vs and volume.vs.__type__ == "lvm":
                vfs.map_file_fh(f"/dev/{volume.raw.vg.name}/{volume.raw.name}", volume)

    def _parse_os_release(self, glob: str | None = None) -> dict[str, str]:
        """Parse files containing Unix version information.

        Not all these files are equal. Generally speaking these files are
        either key=value files or contain just one line.

        Examples of key=value pair structured release files are:
        - /etc/os-release
        - /usr/lib/os-release
        - /etc/lsb-release

        Examples of sparse release files:
        - /etc/fedora-release
        - /etc/centos-release
        - /etc/redhat-release
        - /etc/SuSE-release

        Examples of bsd version files:
        - /bin/freebsd-version
        """
        glob = glob or "/etc/*-release"

        os_release = {}

        for path in self.target.fs.glob(glob):
            if self.target.fs.path(path).is_file():
                with self.target.fs.path(path).open("rt") as release_file:
                    for line in release_file:
                        if line.startswith("#"):
                            continue

                        if "=" not in line:
                            os_release["DISTRIB_DESCRIPTION"] = line.strip()

                        else:
                            try:
                                name, value = line.split("=", maxsplit=1)
                                os_release[name] = value.replace('"', "").replace("\n", "")
                            except ValueError:
                                continue
        return os_release

    def _get_architecture(self, os: str = "unix", path: Path | str = "/bin/ls") -> str | None:
        """Determine architecture by reading an ELF header of a binary on the target.

        Resources:
            - https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#ISA
        """

        if not isinstance(path, TargetPath):
            for fs in [self.target.fs, *self.target.filesystems]:
                if (path := fs.path(path)).exists():
                    break

        if not path.exists():
            return None

        fh = path.open("rb")
        fh.seek(4)  # ELF - e_ident[EI_CLASS]
        bits = fh.read(1)[0]

        fh.seek(18)  # ELF - e_machine
        e_machine = int.from_bytes(fh.read(2), "little")
        arch = ARCH_MAP.get(e_machine, "unknown")

        return f"{arch}_32-{os}" if bits == 1 and arch[-2:] != "32" else f"{arch}-{os}"


def parse_fstab(
    fstab: TargetPath,
    log: logging.Logger = log,
) -> Iterator[tuple[uuid.UUID | str, str, str, str, str]]:
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

        dev, mount_point, fs_type, options, _, _ = entry_parts

        if fs_type in SKIP_FS_TYPES:
            log.warning("Skipped FS type: %s, %s, %s", fs_type, dev, mount_point)
            continue

        dev_id = None
        volume_name = None
        if dev.startswith(("/dev/mapper", "/dev/gpt")):
            volume_name = dev.rsplit("/")[-1]
        elif dev.startswith("/dev/disk/by-uuid"):
            dev_id = dev.rsplit("/")[-1]
        elif dev.startswith("/dev/") and dev.count("/") == 3:
            # When composing a vg-lv name, LVM2 replaces hyphens with double hyphens in the vg and lv names
            # Emulate that here when combining the vg and lv names
            volume_name = "-".join(part.replace("-", "--") for part in dev.rsplit("/")[-2:])
        elif dev.startswith("UUID="):
            dev_id = dev.split("=")[1]
        elif dev.startswith("LABEL="):
            volume_name = dev.split("=")[1]
        elif fs_type == "nfs":
            # Put the nfs server address in dev_id and the root path in volume_name
            dev_id, sep, volume_name = dev.partition(":")
            if sep != ":":
                log.warning("Invalid NFS mount: %s", dev)
                continue
        else:
            log.warning("Unsupported mount device: %s %s", dev, mount_point)
            continue

        if mount_point == "/":
            continue

        if dev_id:
            try:
                dev_id = uuid.UUID(dev_id)
            except ValueError:
                pass

        yield dev_id, volume_name, mount_point, fs_type, options
