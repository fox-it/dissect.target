from __future__ import annotations

import re
from typing import Iterator, Optional

from dissect.target.filesystem import Filesystem, VirtualFilesystem
from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.bsd._os import BsdPlugin
from dissect.target.target import Target

RE_CONFIG_IP = re.compile(r"-IPAddress (?P<ip>[^ ]+) ")
RE_CONFIG_HOSTNAME = re.compile(r"set ns hostName (?P<hostname>[^\n]+)\n")
RE_CONFIG_TIMEZONE = re.compile(
    r'set ns param.* -timezone "GMT\+(?P<hours>[0-9]+):(?P<minutes>[0-9]+)-.*-(?P<zone_name>.+)"'
)
RE_CONFIG_USER = re.compile(r"bind system user (?P<user>[^ ]+) ")
RE_LOADER_CONFIG_KERNEL_VERSION = re.compile(r'kernel="/(?P<version>.*)"')


class CitrixBsdPlugin(BsdPlugin):
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
        newfilesystem = VirtualFilesystem()
        is_citrix = False
        for fs in target.filesystems:
            if fs.exists("/bin/freebsd-version"):
                newfilesystem.map_fs("/", fs)
                break
        for fs in target.filesystems:
            if fs.exists("/nsconfig") and fs.exists("/boot"):
                newfilesystem.map_fs("/flash", fs)
                is_citrix = True
            elif fs.exists("/netscaler"):
                newfilesystem.map_fs("/var", fs)
                is_citrix = True
        if is_citrix:
            return newfilesystem
        return None

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
        nstmp_path = "/var/nstmp/"

        nstmp_user_path = nstmp_path + "{username}"

        for entry in self.target.fs.scandir(nstmp_path):
            if entry.is_dir() and entry.name != "#nsinternal#":
                nstmp_users.add(entry.name)
        for username in self._config_usernames:
            nstmp_home = nstmp_user_path.format(username=username)
            user_home = nstmp_home if self.target.fs.exists(nstmp_home) else None

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
            yield UnixUserRecord(name=username, home=nstmp_user_path.format(username=username))

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.CITRIX.value
