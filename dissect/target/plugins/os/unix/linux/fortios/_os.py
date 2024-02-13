from __future__ import annotations

import gzip
import hashlib
from base64 import b64decode
from datetime import datetime
from io import BytesIO
from tarfile import ReadError
from typing import BinaryIO, Iterator, Optional, TextIO, Union

from dissect.util import cpio
from dissect.util.compression import xz

from dissect.target.filesystem import Filesystem
from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor, UnixUserRecord
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.target import Target

try:
    from Crypto.Cipher import AES, ChaCha20

    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False

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
            "/data/system.conf": "global-config",  # FortiManager
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

                if not self._version and section in ["global-config", "root-config"]:
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
        target.log.warning("Attempting to load rootfs.gz, this can take a while.")
        rootfs = sysvol.path("/rootfs.gz")
        vfs = None

        try:
            if open_decompress(rootfs).read(4) == b"0707":
                vfs = TarFilesystem(rootfs.open(), tarinfo=cpio.CpioInfo)
            else:
                vfs = TarFilesystem(rootfs.open())
        except ReadError:
            # The rootfs.gz file could be encrypted.
            try:
                rfs_fh = decrypt_rootfs(rootfs.open(), get_kernel_hash(sysvol))
                vfs = TarFilesystem(rfs_fh, tarinfo=cpio.CpioInfo)
            except RuntimeError:
                target.log.warning("Could not decrypt rootfs.gz. Missing `pycryptodome` dependency.")
            except ValueError as e:
                target.log.warning("Could not decrypt rootfs.gz. Unsupported kernel version.")
                target.log.debug("", exc_info=e)
            except ReadError as e:
                target.log.warning("Could not mount rootfs.gz. It could be corrupt.")
                target.log.debug("", exc_info=e)

        if vfs:
            target.fs.mount("/", vfs)

        target.fs.mount("/data", sysvol)

        # FortiGate
        if (datafs_tar := sysvol.path("/datafs.tar.gz")).exists():
            target.fs.add_layer().mount("/data", TarFilesystem(datafs_tar.open("rb")))

        # Additional FortiGate or FortiManager tars with corrupt XZ streams
        target.log.warning("Attempting to load XZ files, this can take a while.")
        for path in (
            "bin.tar.xz",
            "usr.tar.xz",
            "migadmin.tar.xz",
            "node-scripts.tar.xz",
            "docker.tar.xz",
            "syntax.tar.xz",
        ):
            if (tar := target.fs.path(path)).exists() or (tar := sysvol.path(path)).exists():
                fh = xz.repair_checksum(tar.open("rb"))
                target.fs.add_layer().mount("/", TarFilesystem(fh))

        # FortiAnalyzer and FortiManager
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
            if fs.__type__ == "ext" and (
                (fs.path("/new_alert_msg").exists() and fs.path("/template").exists())  # FortiGate
                or (fs.path("/swapfile").exists() and fs.path("/old_fmversion").exists())  # FortiManager
            ):
                target.fs.mount("/data2", fs)

        # Symlink unix-like paths
        unix_paths = [("/data/passwd", "/etc/passwd")]
        for src, dst in unix_paths:
            if target.fs.path(src).exists() and not target.fs.path(dst).exists():
                target.fs.symlink(src, dst)

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
        try:
            for entry in self._config["global-config"]["system"]["dns"].values():
                entries.append(entry[0])
        except KeyError:
            pass
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

        # FortiGate administrative users
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

        # FortiManager administrative users
        try:
            for username, entry in self._config["global-config"]["system"]["admin"]["user"].items():
                yield FortiOSUserRecord(
                    name=username,
                    password=":".join(entry.get("password", [])),
                    groups=[entry["profileid"][0]],
                    home="/root",
                    _target=self.target,
                )
        except KeyError as e:
            self.target.log.warning("Exception while parsing FortiManager admin users")
            self.target.log.debug("", exc_info=e)

        # Local users
        try:
            local_groups = local_groups_to_users(self._config["root-config"]["user"]["group"])
            for username, entry in self._config["root-config"]["user"].get("local", {}).items():
                try:
                    password = decrypt_password(entry["passwd"][-1])
                except (ValueError, RuntimeError):
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
                except (ValueError, RuntimeError):
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
        paths = ["/lib/libav.so", "/bin/ctr"]
        for path in paths:
            if self.target.fs.path(path).exists():
                return self._get_architecture(path=path)


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
        version_str = input.split(":", 1)[0].strip()
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


def decrypt_password(input: str) -> str:
    """Decrypt FortiOS encrypted secrets.

    Works for FortiGate 5.x, 6.x and 7.x (CVE-2019-6693).

    NOTE:
        - FortiManager uses a 16-byte IV and is not supported (CVE-2020-9289).
        - FortiGate 4.x uses DES and a static 8-byte key and is not supported.

    Returns decoded plaintext or original input ciphertext when decryption failed.

    Resources:
        - https://www.fortiguard.com/psirt/FG-IR-19-007
    """

    if not HAS_PYCRYPTODOME:
        raise RuntimeError("PyCryptodome module not available")

    if input[:3] in ["SH2", "AK1"]:
        raise ValueError("Password is a hash (SHA-256 or SHA-1) and cannot be decrypted.")

    ciphertext = b64decode(input)
    iv = ciphertext[:4] + b"\x00" * 12
    key = b"Mary had a littl"
    cipher = AES.new(key, iv=iv, mode=AES.MODE_CBC)
    plaintext = cipher.decrypt(ciphertext[4:])

    try:
        return plaintext.split(b"\x00", 1)[0].decode()
    except UnicodeDecodeError:
        return "ENC:" + input


def decrypt_rootfs(fh: BinaryIO, kernel_hash: str) -> BinaryIO:
    """Attempt to decrypt an encrypted ``rootfs.gz`` file.

    FortiOS releases as of 7.4.1 / 2023-08-31, have ChaCha20 encrypted ``rootfs.gz`` files.
    This function attempts to decrypt a ``rootfs.gz`` file using a static key and IV
    which can be found in the kernel.

    Currently supported versions (each release has a new key):
        - FortiGate VM 7.0.13
        - FortiGate VM 7.0.14
        - FortiGate VM 7.4.1
        - FortiGate VM 7.4.2
        - FortiGate VM 7.4.3

    Resources:
        - https://docs.fortinet.com/document/fortimanager/7.4.2/release-notes/519207/special-notices
        - Reversing kernel (fgt_verifier_iv, fgt_verifier_decrypt, fgt_verifier_initrd)
    """

    if not HAS_PYCRYPTODOME:
        raise RuntimeError("PyCryptodome module not available")

    # SHA256 hashes of kernel files
    KERNEL_KEY_MAP = {
        # FortiGate VM 7.0.13
        "25cb2c8a419cde1f42d38fc6cbc95cf8b53db41096d0648015674d8220eba6bf": (
            bytes.fromhex("c87e13e1f7d21c1aca81dc13329c3a948d6e420d3a859f3958bd098747873d08"),
            bytes.fromhex("87486a24637e9a66f09ec182eee25594"),
        ),
        # FortiGate VM 7.0.14
        "67d4c913b1ceb7a62e2076ca835ebfdc67e65c7716fc604caa7552512f171197": (
            bytes.fromhex("9ba00c035bcaa97717d936f8268a973eb1dd64d19388153fad5f7849b8fdf0d8"),
            bytes.fromhex("9df4ba40dbddcf5ec9d2983681eb1940"),
        ),
        # FortiGate VM 7.4.1
        "a008b47327293e48502a121ee8709f243ad5da4e63d6f663c253db27bd01ea28": _kdf_7_4_x(
            "366486c0f2c6322ec23e4f33a98caa1b19d41c74bb4f25f6e8e2087b0655b30f"
        ),
        # FortiGate VM 7.4.2
        "c392cf83ab484e0b2419b2711b02cdc88a73db35634c10340037243394a586eb": _kdf_7_4_x(
            "480767be539de28ee773497fa731dd6368adc9946df61da8e1253fa402ba0302"
        ),
        # FortiGate VM 7.4.3
        "ba0450947e51844588b29bd302d2a1a3802f7718cf6840011c1b34f1c1f0bb89": _kdf_7_4_x(
            "4cf7a950b99cf29b0343e7ba6c609e49d9766f16c6d2f075f72ad400542f0765"
        ),
    }

    if not (key_data := KERNEL_KEY_MAP.get(kernel_hash)):
        raise ValueError("Failed to decrypt: Unknown kernel hash.")

    key, iv = key_data
    # First 8 bytes = counter, last 8 bytes = nonce
    # PyCryptodome interally divides this seek by 64 to get a (position, offset) tuple
    # We're interested in updating the position in the ChaCha20 internal state, so to make
    # PyCryptodome "OpenSSL-compatible" we have to multiply the counter by 64
    cipher = ChaCha20.new(key=key, nonce=iv[8:])
    cipher.seek(int.from_bytes(iv[:8], "little") * 64)
    result = cipher.decrypt(fh.read())

    if result[0:2] != b"\x1f\x8b":
        raise ValueError("Failed to decrypt: No gzip magic header found.")

    return BytesIO(result)


def _kdf_7_4_x(key_data: Union[str, bytes]) -> tuple[bytes, bytes]:
    """Derive 32 byte key and 16 byte IV from 32 byte seed.

    As the IV needs to be 16 bytes, we return the first 16 bytes of the sha256 hash.
    """

    if isinstance(key_data, str):
        key_data = bytes.fromhex(key_data)

    key = hashlib.sha256(key_data[4:32] + key_data[:4]).digest()
    iv = hashlib.sha256(key_data[5:32] + key_data[:5]).digest()[:16]
    return key, iv


def get_kernel_hash(sysvol: Filesystem) -> Optional[str]:
    """Return the SHA256 hash of the (compressed) kernel."""
    kernel_files = ["flatkc", "vmlinuz", "vmlinux"]
    for k in kernel_files:
        if sysvol.path(k).exists():
            return sysvol.sha256(k)
