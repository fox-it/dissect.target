from __future__ import annotations

import re
from typing import Iterator, Optional

from dissect.target.filesystem import Filesystem
from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix._os import UnixPlugin
from dissect.target.plugins.os.unix.bsd._os import BsdPlugin
from dissect.target.target import Target

RE_CONFIG_IP = re.compile(r"-IPAddress (?P<ip>[^ ]+) ")
RE_CONFIG_HOSTNAME = re.compile(r"set ns hostName (?P<hostname>[^\n]+)\n")
RE_CONFIG_TIMEZONE = re.compile(
    r'set ns param.* -timezone "GMT\+(?P<hours>[0-9]+):(?P<minutes>[0-9]+)-.*-(?P<zone_name>.+)"'
)
RE_CONFIG_USER = re.compile(r"bind system user (?P<user>[^ ]+) ")
RE_LOADER_CONFIG_KERNEL_VERSION = re.compile(r'kernel="/(?P<version>.*)"')


class CitrixPlugin(BsdPlugin):
    def __init__(self, target: Target):
        super().__init__(target)
        self._ips = []
        self._hostname = None
        self.config_usernames = []
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
                    if timezone_match := RE_CONFIG_TIMEZONE.search(config):
                        tzinfo = timezone_match.groupdict()
                        self.target.timezone = tzinfo["zone_name"]

        self._config_usernames = list(usernames)
        self._ips = list(ips)

    @classmethod
    def detect(cls, target: Target) -> Optional[Filesystem]:
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
    def create(cls, target: Target, sysvol: Filesystem) -> UnixPlugin:
        # A disk image of a Citrix Netscaler contains two partitions, that after boot are mounted to /var and /flash.
        # The rest of the filesystem is recreated at runtime into a 'ramdisk'. Currently, this plugin does not
        # yet support recreating the ramdisk from a 'clean' state. This might be possible in a future iteration but
        # requires further research.

        # When the ramdisk is present within the target's filesystems, mount it accordingly,
        for fs in target.filesystems:
            if fs.exists("/bin/freebsd-version"):
                # If available, mount the ramdisk first.
                target.fs.mount("/", fs)
        # The 'disk' filesystem is mounted at '/var'.
        target.fs.mount("/var", sysvol)

        # Enumerate filesystems for flash partition
        for fs in target.filesystems:
            if fs.exists("/nsconfig") and fs.exists("/boot"):
                target.fs.mount("/flash", fs)

        return cls(target)

    @export(property=True)
    def hostname(self) -> Optional[str]:
        return self._hostname

    @export(property=True)
    def version(self) -> Optional[str]:
        version = "Unknown"
        version_path = self.target.fs.path("/flash/.version")
        if version_path.is_file():
            version = version_path.read_text().strip()

        loader_conf_path = self.target.fs.path("/flash/boot/loader.conf")
        if loader_conf_path.is_file():
            loader_conf = loader_conf_path.read_text()
            if match := RE_LOADER_CONFIG_KERNEL_VERSION.search(loader_conf):
                kernel_version = match.groupdict()["version"]
                version = f"{version} ({kernel_version})" if version else kernel_version

        if not version:
            self.target.log.warn("Could not determine kernel version")

        return version

    @export(property=True)
    def ips(self) -> list[str]:
        return self._ips

    @export(record=UnixUserRecord)
    def users(self) -> Iterator[UnixUserRecord]:
        nstmp_users = set()
        nstmp_path = self.target.fs.path("/var/nstmp/")

        if nstmp_path.exists():
            for entry in nstmp_path.iterdir():
                if entry.is_dir() and entry.name != "#nsinternal#":
                    nstmp_users.add(entry.name)

        for username in self._config_usernames:
            nstmp_home = nstmp_path.joinpath(username)
            user_home = nstmp_home if nstmp_home.exists() else None

            if user_home:
                # After this loop we will yield all users who are not in the config, but are listed in /var/nstmp/
                # To prevent double records, we remove entries from the set that we are already yielding here.
                nstmp_users.remove(username)

            if username == "root" and self.target.fs.exists("/root"):
                # If we got here, 'root' is present both in /var/nstmp and in /root. In such cases, we yield
                # the 'root' user as having '/root' as a home, not in /var/nstmp.
                user_home = "/root"

            yield UnixUserRecord(name=username, home=user_home)

        for username in nstmp_users:
            yield UnixUserRecord(name=username, home=nstmp_path.joinpath(username))

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.CITRIX.value
