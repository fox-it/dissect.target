from __future__ import annotations

import gzip
from base64 import b64decode
from datetime import datetime
from tarfile import ReadError
from typing import Iterator, Optional, TextIO, Union

from Crypto.Cipher import AES
from dissect.util import cpio
from dissect.util.compression import xz

from dissect.target.filesystem import Filesystem
from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor, UnixUserRecord
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.target import Target

FortiOSUserRecord = TargetRecordDescriptor(
    "fortios/user",
    [
        ("string", "name"),
        ("string[]", "groups"),
        ("string", "password"),
        ("path", "home"),
    ],
)


class FortiOSPlugin(LinuxPlugin):
    """FortiOS plugin for various Fortinet appliances."""

    def __init__(self, target: Target):
        super().__init__(target)
        self._version = None
        self._config = self._load_config()

    def _load_config(self) -> dict:
        CONFIG_FILES = {
            "/data/system.conf": None,
            "/data/config/daemon.conf.gz": "daemon",  # FortiOS 4.x
            "/data/config/sys_global.conf.gz": "global-config",  # Seen in FortiOS 5.x - 7.x
            "/data/config/sys_vd_root.conf.gz": "root-config",  # FortiOS 4.x
            "/data/config/sys_vd_root+root.conf.gz": "root-config",  # Seen in FortiOS 6.x - 7.x
            "/data/config/global_system_interface.gz": "interfaces",  # Seen in FortiOS 5.x - 7.x
        }

        config = {}
        for conf_file, section in CONFIG_FILES.items():
            if (conf_path := self.target.fs.path(conf_file)).exists():
                if conf_file.endswith("gz"):
                    fh = gzip.open(conf_path.open("rb"), "rt")
                else:
                    fh = conf_path.open("rt")

                if not self._version and section in [None, "global-config", "root-config"]:
                    self._version = fh.readline().split("=", 1)[1]

                parsed = FortiOSConfig.from_fh(fh)
                config |= {section: parsed} if section else parsed

        return config

    @classmethod
    def detect(cls, target: Target) -> Optional[Filesystem]:
        for fs in target.filesystems:
            # Tested on FortiGate and FortiAnalyzer, other Fortinet devices may look different.
            if fs.exists("/rootfs.gz") and (fs.exists("/.fgtsum") or fs.exists("/.fmg_sign") or fs.exists("/flatkc")):
                return fs

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> FortiOSPlugin:
        rootfs = sysvol.path("/rootfs.gz")

        try:
            target.log.warning("Attempting to load compressed rootfs.gz, this can take a while.")
            rfs_fh = open_decompress(rootfs)
            if rfs_fh.read(4) == b"07" * 2:
                vfs = TarFilesystem(rootfs.open(), tarinfo=cpio.CpioInfo)
            else:
                vfs = TarFilesystem(rootfs.open())
            target.fs.mount("/", vfs)
        except ReadError as e:
            # Since FortiOS version ~7.4.1 the rootfs.gz file is encrypted.
            target.log.warning("Could not mount FortiOS `/rootfs.gz`. It could be encrypted or corrupt.")
            target.log.debug("", exc_info=e)

        target.fs.mount("/data", sysvol)

        # FortiGate
        if (datafs_tar := sysvol.path("/datafs.tar.gz")).exists():
            target.fs.add_layer().mount("/data", TarFilesystem(datafs_tar.open("rb")))

        # Additional FortiGate tars with corrupt XZ streams
        for path in ("bin.tar.xz", "usr.tar.xz", "migadmin.tar.xz", "node-scripts.tar.xz"):
            if (tar := target.fs.path(path)).exists():
                fh = xz.repair_checksum(tar.open("rb"))
                target.fs.add_layer().mount("/", TarFilesystem(fh))

        # FortiAnalyzer
        if (rootfs_ext_tar := sysvol.path("rootfs-ext.tar.xz")).exists():
            target.fs.add_layer().mount("/", TarFilesystem(rootfs_ext_tar.open("rb")))

        # Filesystem mounts can be discovered in the FortiCare debug report
        # or using ``fnsysctl ls`` and ``fnsysctl df`` in the cli.
        for fs in target.filesystems:
            # log partition
            if fs.__type__ == "ext" and (
                fs.extfs.volume_name.startswith("LOGUSEDX") or fs.path("/root/clog").is_symlink()
            ):
                target.fs.mount("/var/log", fs)

            # EFI partition
            if fs.__type__ == "fat" and fs.path("/EFI").exists():
                target.fs.mount("/boot", fs)

            # data2 partition
            if fs.__type__ == "ext" and fs.path("/new_alert_msg").exists() and fs.path("/template").exists():
                target.fs.mount("/data2", fs)

        return cls(target)

    @export(property=True)
    def hostname(self) -> str | None:
        """Return configured hostname."""
        try:
            return self._config["global-config"]["system"]["global"]["hostname"][0]
        except KeyError:
            return None

    @export(property=True)
    def ips(self) -> list[str]:
        """Return IP addresses of configured interfaces."""
        result = []

        try:
            # FortiOS 6 and 7 (from global_system_interface.gz)
            for key, iface in self._config["interfaces"].items():
                if not key.startswith("port"):
                    continue
                result += [ip for ip in iface["ip"] if not ip.startswith("255")]
        except KeyError as e:
            self.target.log.debug("Exception while parsing FortiOS interfaces", exc_info=e)

        try:
            # Other versions
            for conf in self._config["global-config"]["system"]["interface"].values():
                if "ip" in conf:
                    result.append(conf.ip[0])
        except KeyError as e:
            self.target.log.debug("Exception while parsing FortiOS system interfaces", exc_info=e)

        return result

    @export(property=True)
    def dns(self) -> list[str]:
        """Return configured WAN DNS servers."""
        entries = []
        for _, entry in self._config["global-config"]["system"]["dns"].items():
            entries.append(entry[0])
        return entries

    @export(property=True)
    def version(self) -> str:
        """Return FortiOS version."""
        if self._version:
            return parse_version(self._version)
        return "FortiOS Unknown"

    @export(record=FortiOSUserRecord)
    def users(self) -> Iterator[Union[FortiOSUserRecord, UnixUserRecord]]:
        """Return local users of the FortiOS system."""

        # Possible unix-like users
        yield from super().users()

        # Administrative users
        try:
            for username, entry in self._config["global-config"]["system"]["admin"].items():
                yield FortiOSUserRecord(
                    name=username,
                    password=":".join(entry.get("password", [])),
                    groups=[entry["accprofile"][0]],
                    home="/root",
                    _target=self.target,
                )
        except KeyError as e:
            self.target.log.warning("Exception while parsing FortiOS admin users")
            self.target.log.debug("", exc_info=e)

        # Local users
        try:
            local_groups = local_groups_to_users(self._config["root-config"]["user"]["group"])
            for username, entry in self._config["root-config"]["user"].get("local", {}).items():
                try:
                    password = decrypt_password(entry["passwd"][-1])
                except ValueError:
                    password = ":".join(entry.get("passwd", []))

                yield FortiOSUserRecord(
                    name=username,
                    password=password,
                    groups=local_groups.get(username, []),
                    home=None,
                    _target=self.target,
                )
        except KeyError as e:
            self.target.log.warning("Exception while parsing FortiOS local users")
            self.target.log.debug("", exc_info=e)

        # Temporary guest users
        try:
            for _, entry in self._config["root-config"]["user"]["group"].get("guestgroup", {}).get("guest", {}).items():
                try:
                    password = decrypt_password(entry.get("password")[-1])
                except ValueError:
                    password = ":".join(entry.get("password"))

                yield FortiOSUserRecord(
                    name=entry["user-id"][0],
                    password=password,
                    groups=["guestgroup"],
                    home=None,
                    _target=self.target,
                )
        except KeyError as e:
            self.target.log.warning("Exception while parsing FortiOS temporary guest users")
            self.target.log.debug("", exc_info=e)

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.FORTIOS.value

    @export(property=True)
    def architecture(self) -> Optional[str]:
        """Return architecture FortiOS runs on."""
        return self._get_architecture(path="/lib/libav.so")


class ConfigNode(dict):
    def set(self, path: list[str], value: str) -> None:
        node = self

        for part in path[:-1]:
            if part not in node:
                node[part] = ConfigNode()
            node = node[part]

        node[path[-1]] = value

    def __getattr__(self, attr: str) -> ConfigNode | str:
        return self[attr]


class FortiOSConfig(ConfigNode):
    @classmethod
    def from_fh(cls, fh: TextIO) -> FortiOSConfig:
        root = cls()

        stack = []
        for parts in _parse_config(fh):
            cmd = parts[0]

            if cmd == "config":
                if parts[1] == "vdom" and stack == [["vdom"]]:
                    continue

                stack.append(parts[1:])

            elif cmd == "edit":
                stack.append(parts[1:])

            elif cmd == "end":
                if stack:
                    stack.pop()

            elif cmd == "next":
                if stack:
                    stack.pop()

            elif cmd == "set":
                path = []
                for part in stack:
                    path += part

                path.append(parts[1])
                root.set(path, parts[2:])

        return root


def _parse_config(fh: TextIO) -> Iterator[list[str]]:
    parts = []
    string = None

    for line in fh:
        if not (line := line.strip()) or line.startswith("#"):
            continue

        for part in line.split(" "):
            if part.startswith('"'):
                if part.endswith('"'):
                    parts.append(part[1:-1])
                else:
                    string = [part[1:]]
            elif part.endswith('"') and part[-2] != "\\":
                string.append(part[:-1])
                parts.append(" ".join(string))
                string = None
            elif string:
                string.append(part)
            else:
                parts.append(part)

        if string:
            string.append("\n")

        if parts and not string:
            yield parts
            parts = []


def parse_version(input: str) -> str:
    """Attempt to parse the config FortiOS version to a readable format.

    The input ``FGVM64-7.4.1-FW-build2463-230830:opmode=0:vdom=0`` would
    return the following output: ``FortiGate VM 7.4.1 (build 2463, 2023-08-30)``.

    Resources:
        - https://support.fortinet.com/Download/VMImages.aspx
    """

    PREFIXES = {
        "FGV": "FortiGate VM",  # FGVM64
        "FGT": "FortiGate",  # can also be FGT-VM in 4.x/5.x
        "FMG": "FortiManager",
        "FAZ": "FortiAnalyzer",
        "FFW": "FortiFirewall",
        "FOS": "FortiOS",
        "FWB": "FortiWeb",
        "FAD": "FortiADC",
    }

    try:
        version_str = input.split(":", 1)[0]
        type, version, _, build_num, build_date = version_str.rsplit("-", 4)

        build_num = build_num.replace("build", "build ", 1)
        build_date = datetime.strptime(build_date, "%y%m%d").strftime("%Y-%m-%d")
        type = PREFIXES.get(type[:3], type)

        return f"{type} {version} ({build_num}, {build_date})"
    except ValueError:
        return input


def local_groups_to_users(config_groups: dict) -> dict:
    """Map FortiOS groups to a dict with usernames as key."""
    user_groups = {}
    for group, items in config_groups.items():
        for user in items.get("member", []):
            if user in user_groups:
                user_groups[user].append(group)
            else:
                user_groups[user] = [group]
    return user_groups


def decrypt_password(ciphertext: str) -> str:
    """Decrypt FortiOS version 6 and 7 encrypted secrets."""

    if ciphertext[:3] in ["SH2", "AK1"]:
        raise ValueError("Password is a hash (SHA-256 or SHA-1) and cannot be decrypted.")

    ciphertext = b64decode(ciphertext)
    iv = ciphertext[:4] + b"\x00" * 12
    key = b"Mary had a littl"
    cipher = AES.new(key, iv=iv, mode=AES.MODE_CBC)
    plaintext = cipher.decrypt(ciphertext[4:])
    return plaintext.split(b"\x00", 1)[0].decode()
