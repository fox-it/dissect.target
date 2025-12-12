from __future__ import annotations

import gzip
import re
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.util.stream import RangeStream

from dissect.target.filesystems.ffs import FfsFilesystem
from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.bsd._os import BsdPlugin

try:
    from dissect.executable import ELF

    HAS_EXECUTABLE = True

except ImportError:
    HAS_EXECUTABLE = False

if TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target

RE_CONFIG_IP = re.compile(r"-IPAddress (?P<ip>[^ ]+) ")
RE_CONFIG_HOSTNAME = re.compile(r"set ns hostName (?P<hostname>[^\n]+)\n")
RE_CONFIG_TIMEZONE = re.compile(
    r'set ns param.* -timezone "GMT\+(?P<hours>[0-9]+):(?P<minutes>[0-9]+)-.*-(?P<zone_name>.+)"'
)
RE_CONFIG_USER = re.compile(r"bind system user (?P<user>[^ ]+) ")
RE_LOADER_CONFIG_KERNEL_VERSION = re.compile(r'kernel="/(?P<version>.*)"')


class CitrixPlugin(BsdPlugin):
    """Citrix Netscaler OS plugin."""

    def __init__(self, target: Target):
        super().__init__(target)
        self._ips = []
        self._hostname = None
        self._config_usernames = []
        self._parse_netscaler_configs()

    def _parse_netscaler_configs(self) -> None:
        ips = set()
        usernames = set()
        for config_path in self.target.fs.path("/flash/nsconfig/").glob("ns.conf*"):
            with config_path.open("rt") as config_file:
                config = config_file.read()
                for match in RE_CONFIG_IP.finditer(config):
                    ips.add(match.groupdict()["ip"])
                for match in RE_CONFIG_USER.finditer(config):
                    usernames.add(match.groupdict()["user"])
                if config_path.name == "ns.conf":
                    # Current configuration of the netscaler
                    if hostname_match := RE_CONFIG_HOSTNAME.search(config):
                        self._hostname = hostname_match.groupdict()["hostname"]
                    # Collect timezone from nsconfig/ns.conf or from shell/date.out if exists
                    if timezone_match := RE_CONFIG_TIMEZONE.search(config):
                        tzinfo = timezone_match.groupdict()
                        self.target.timezone = tzinfo["zone_name"]
                    # Netscaler collector specific check:
                    elif self.target.fs.path("/shell/date.out").exists():
                        # If timezone not set in ns.conf it is often UTC, lets check for that.
                        if "UTC" in self.target.fs.path("/shell/date.out").open("rt").read():
                            self.target.timezone = "UTC"

        self._config_usernames = list(usernames)
        self._ips = list(ips)

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        ramdisk = None
        for fs in target.filesystems:
            # /netscaler can be present on both the ramdisk and the harddisk. Therefore we also check for the /log
            # folder, which is not present on the ramdisk. We regard the harddisk as the system volume, as it is
            # possible to only have a disk image of a Netscaler. However, in the case where we only have the ramdisk,
            # we want to fall back on that as the system volume. Thus we store that filesystem in a fallback variable.
            if fs.exists("/netscaler"):
                if fs.exists("/log"):
                    return fs
                ramdisk = fs

        # At this point, we could not find the filesystem for '/var'. Thus, we fall back to the ramdisk variable, which
        # is either 'None' (in which case this isn't a Citrix netscaler), or points to the filesystem of the ramdisk.
        return ramdisk

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> Self:
        """Map filesystems as the Citrix Netscaler bootloader would.

        An image of a Citrix Netscaler generally contains two partitions, that after boot are mounted
        to ``/var``and ``/flash``. The rest of the filesystem is recreated at runtime into a 'ramdisk'.
        This ramdisk is generally stored read-only in the kernel ELF binary located in ``/flash/ns-*.gz``.

        This implementation supports mapping a live ramdisk which is already mounted at ``/`` and also
        supports extracting the read-only kernel FFS filesystem from ``/flash/ns-*.gz`` and mounting at ``/``.
        """

        # When the ramdisk is already present within the target's filesystems, mount it accordingly.
        has_ramdisk = False
        for fs in target.filesystems:
            if fs.exists("/bin/freebsd-version"):
                # If available, mount the ramdisk first.
                target.fs.mount("/", fs)
                has_ramdisk = True

        # Check if we are dealing with netscaler-collector filesystem (/shell exists) or full image
        if sysvol.exists("/shell"):
            target.fs.mount("/", sysvol)
        else:
            # The 'disk' filesystem is mounted at '/var'.
            target.fs.mount("/var", sysvol)

        # Enumerate filesystems for flash partition.
        # Multiple flash partitions could exist, so we look for the one with an actual ns.conf present.
        for fs in target.filesystems:
            if fs.exists("/nsconfig/ns.conf") and fs.exists("/boot"):
                target.fs.mount("/flash", fs)

        # Reconstruct root filesystem from the 'mfs' segment embedded in the kernel.
        if (
            not has_ramdisk
            and (boot_loader_conf := target.fs.path("/flash/boot/loader.conf")).is_file()
            and (match := RE_LOADER_CONFIG_KERNEL_VERSION.search(boot_loader_conf.read_text()))
        ):
            # Finds the currently active kernel version.
            kernel_version = match.groupdict()["version"]

            if (kernel_gz := target.fs.path(f"/flash/{kernel_version}.gz")).is_file():
                if HAS_EXECUTABLE:
                    target.log.warning("Loading compressed kernel filesystem, this can take a while")

                    try:
                        # This is *significantly* faster than decompressing random reads on the fly.
                        fh = BytesIO(gzip.decompress(kernel_gz.read_bytes()))

                        # Obtain the offset and size of the mfs section.
                        section = ELF(fh).sections.by_name("mfs")[0]

                        # Construct a FFS filesystem and add it to the target.
                        fs = FfsFilesystem(RangeStream(fh, section.offset, section.size))

                        target.filesystems.add(fs)
                        target.fs.mount("/", fs)

                    except Exception as e:
                        target.log.error("Failed to load kernel filesystem: %s", e)  # noqa: TRY400
                        target.log.debug("", exc_info=e)

                else:
                    target.log.warning("Unable to load kernel filesystem, missing dependency dissect.executable")

            else:
                target.log.warning("File %s not found, did not load Netscaler kernel in root filesystem", kernel_gz)

        return cls(target)

    @export(property=True)
    def hostname(self) -> str | None:
        # Could be set in ns.conf file(s)
        if self._hostname:
            return self._hostname

        # Could be found in license file(s)
        if (dir := self.target.fs.path("/flash/nsconfig/license")).is_dir():
            hostname = None
            for lic in dir.glob("*.lic"):
                for line in lic.open("rt"):
                    if "HOSTNAME=" in line:
                        hostname = line.split("HOSTNAME=")[-1].strip()
            if hostname:
                return hostname

        # Fallback to BSD hostname file(s)
        return super().hostname

    @export(property=True)
    def version(self) -> str | None:
        version = "Unknown"
        version_path = self.target.fs.path("/flash/.version")
        if version_path.is_file():
            version = version_path.read_text().strip()

        # Loader.conf exists in different location for NS image vs Techsupport Collection
        for config_path in ["/flash/boot/loader.conf", "nsconfig/loader.conf"]:
            config = self.target.fs.path(config_path)
            if not config.is_file():
                continue

            if match := RE_LOADER_CONFIG_KERNEL_VERSION.search(config.read_text()):
                kernel_version = match.groupdict()["version"]
                version = f"{version} ({kernel_version})" if version else kernel_version

        if not version:
            self.target.log.warning("Could not determine kernel version")

        return version

    @export(property=True)
    def ips(self) -> list[str]:
        return self._ips

    @export(record=UnixUserRecord)
    def users(self) -> Iterator[UnixUserRecord]:
        nstmp_users = set()
        seen = set()
        nstmp_path = self.target.fs.path("/var/nstmp/")

        # Build a set of nstmp users
        if nstmp_path.exists():
            for entry in nstmp_path.iterdir():
                if entry.is_dir() and entry.name != "#nsinternal#":
                    # The nsmonitor user has a home directory of /var/nstmp/monitors rather than /var/nstmp/nsmonitor
                    username = "nsmonitor" if entry.name == "monitors" else entry.name
                    nstmp_users.add(username)

        # Yield users from the config, matching them to their 'home' in /var/nstmp if it exists.
        for username in self._config_usernames:
            nstmp_home = nstmp_path.joinpath(username)
            user_home = nstmp_home if nstmp_home.exists() else None

            if user_home:
                # After this loop we will yield all users who are not in the config, but are listed in /var/nstmp/
                # To prevent double records, we remove entries from the set that we are already yielding here.
                nstmp_users.remove(username)

            if username == "root" and self.target.fs.exists("/root"):
                # If we got here, 'root' is present both in /var/nstmp and in /root. In such cases, we yield
                # the 'root' user as having '/root' as a home, not in /var/nstmp, as there is no 'nscli_history'
                # for the root user in /var/nstmp.
                user_home = self.target.fs.path("/root")

            seen.add((username, user_home.as_posix() if user_home else None, None))
            yield UnixUserRecord(name=username, home=user_home)

        # Yield all users in nstmp that were not observed in the config
        for username in nstmp_users:
            # The nsmonitor user has a home directory of /var/nstmp/monitors rather than /var/nstmp/nsmonitor
            home = nstmp_path.joinpath(username) if username != "nsmonitor" else nstmp_path.joinpath("monitors")
            seen.add((username, home.as_posix(), None))
            yield UnixUserRecord(name=username, home=home)

        # Yield users from /etc/passwd if we have not seem them in previous loops
        for user in super().users():
            if (user.name, user.home.as_posix(), user.shell) in seen:
                continue
            # To prevent bogus command history for all users without a home whenever a history is located at the root
            # of the filesystem, we set the user home to None if their home is equivalent to '/'
            user.home = user.home if user.home != "/" else None
            yield user

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.CITRIX.value
