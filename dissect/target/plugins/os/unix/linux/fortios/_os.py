from __future__ import annotations

import gzip
import io
from base64 import b64decode
from binascii import crc32
from datetime import datetime
from tarfile import ReadError
from typing import BinaryIO, Iterator, Optional, TextIO

from Crypto.Cipher import AES
from dissect.util import cpio, ts
from dissect.util.stream import OverlayStream

from dissect.target.filesystem import Filesystem
from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.target import Target

FortiOSUserRecord = TargetRecordDescriptor(
    "fortios/user",
    [
        ("string", "name"),
        ("string", "groups"),
        ("string", "password"),
        ("path", "home"),
    ],
)


class FortiOSPlugin(LinuxPlugin):
    """FortiOS Dissect Plugin"""

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
                fh = repair_lzma_stream(tar.open("rb"))
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
        """Return configured hostname"""
        try:
            return self._config["global-config"]["system"]["global"]["hostname"][0]
        except KeyError:
            return None

    @export(property=True)
    def ips(self) -> list[str]:
        """Return ip addresses of configured interfaces"""
        result = []

        try:
            # FortiOS 6 and 7 (from global_system_interface.gz)
            for key, iface in self._config["interfaces"].items():
                if not key.startswith("port"):
                    continue
                result += [ip for ip in iface["ip"] if not ip.startswith("255")]

            # Other versions
            for conf in self._config["global-config"]["system"]["interface"].values():
                if "ip" in conf:
                    result.append(conf.ip[0])
        except KeyError:
            pass

        return result

    @export(property=True)
    def version(self) -> str:
        """Return FortiOS version"""
        if self._version:
            return parse_version(self._version)
        return "FortiOS Unknown"

    @export(property=True)
    def os(self) -> str:
        """Return `fortios`"""
        return OperatingSystem.FORTIOS.value

    @export(record=FortiOSUserRecord)
    def users(self) -> Iterator[FortiOSUserRecord]:
        """Return local users of the FortiOS system"""

        # Administrative users
        for username, entry in self._config["global-config"]["system"]["admin"].items():
            yield FortiOSUserRecord(
                name=username,
                password=":".join(entry.get("password", [])),
                groups=entry["accprofile"][0],
                home="/root",
                _target=self.target,
            )

        # Local users
        local_groups = local_groups_to_users(self._config["root-config"]["user"]["group"])
        for username, entry in self._config["root-config"]["user"].get("local", {}).items():
            try:
                password = decrypt_password(entry["passwd"][-1])
            except ValueError:
                password = ":".join(entry.get("passwd", []))

            yield FortiOSUserRecord(
                name=username,
                password=password,
                groups=",".join(local_groups.get(username, [])),
                home=None,
                _target=self.target,
            )

        # Temporary guest users
        for _, entry in self._config["root-config"]["user"]["group"].get("guestgroup", {}).get("guest", {}).items():
            try:
                password = decrypt_password(entry.get("password")[-1])
            except ValueError:
                password = ":".join(entry.get("password"))

            yield FortiOSUserRecord(
                name=entry["user-id"][0],
                password=password,
                groups="guestgroup",
                home=None,
                _target=self.target,
            )

    @export(property=True)
    def dns(self) -> list[str]:
        """Return configured WAN DNS servers"""
        entries = []
        for _, entry in self._config["global-config"]["system"]["dns"].items():
            entries.append(entry[0])
        return entries

    @export(property=True)
    def install_date(self) -> Optional[str]:
        """Return the likely install date of the operating system"""
        if (init_log := self.target.fs.path("/data/etc/cloudinit.log")).exists():
            return ts.from_unix(init_log.stat().st_mtime)

    @export(property=True)
    def timezone(self):
        """Return configured UI/system timezone."""
        timezone_num = self._config["global-config"]["system"]["global"]["timezone"][0]
        return translate_timezone(timezone_num)

    @export(property=True)
    def language(self):
        """Return configured UI language."""
        LANG_MAP = {
            "english": "en_US",
            "french": "fr_FR",
            "spanish": "es_ES",
            "portuguese": "pt_PT",
            "japanese": "ja_JP",
            "trach": "zh_TW",
            "simch": "zh_CN",
            "korean": "ko_KR",
        }
        lang_str = self._config["global-config"]["system"]["global"].get("language", ["english"])[0]
        return LANG_MAP.get(lang_str, lang_str)

    @export(property=True)
    def architecture(self):
        """Return architecture FortiOS runs on"""
        return self._get_architecture(custom_file="/lib/libav.so")


def repair_lzma_stream(fh: BinaryIO) -> BinaryIO:
    """Repair CRC32 checksums for all headers in an XZ stream.

    Fortinet XZ files have (on purpose) corrupt streams which they read using a modified ``xz`` binary.
    The only thing changed are the CRC32 checksums, so partially parse the XZ file and fix all of them.

    References:
        - https://tukaani.org/xz/xz-file-format-1.1.0.txt
        - https://github.com/Rogdham/python-xz

    Args:
        fh: A file-like object of an LZMA stream to repair.
    """
    size = fh.seek(0, io.SEEK_END)
    repaired = OverlayStream(fh, size)
    fh.seek(0)

    header = fh.read(12)
    # Check header magic
    if header[:6] != b"\xfd7zXZ\x00":
        raise ValueError("Not an XZ file")
    # Add correct header CRC32
    repaired.add(8, _crc32(header[6:8]))

    fh.seek(-12, io.SEEK_END)
    footer = fh.read(12)
    # Check footer magic
    if footer[10:12] != b"YZ":
        raise ValueError("Not an XZ file")
    # Add correct footer CRC32
    repaired.add(fh.tell() - 12, _crc32(footer[4:10]))

    backward_size = (int.from_bytes(footer[4:8], "little") + 1) * 4
    fh.seek(-12 - backward_size, io.SEEK_END)
    index = fh.read(backward_size)
    # Add correct index CRC32
    repaired.add(fh.tell() - 4, _crc32(index[:-4]))

    # Parse the index
    isize, nb_records = _mbi(index[1:])
    index = index[1 + isize : -4]
    records = []
    for _ in range(nb_records):
        if not index:
            raise ValueError("index size")
        isize, unpadded_size = _mbi(index)
        if not unpadded_size:
            raise ValueError("index record unpadded size")
        index = index[isize:]
        if not index:
            raise ValueError("index size")
        isize, uncompressed_size = _mbi(index)
        if not uncompressed_size:
            raise ValueError("index record uncompressed size")
        index = index[isize:]
        records.append((unpadded_size, uncompressed_size))

    block_start = size - 12 - backward_size
    blocks_len = sum((unpadded_size + 3) & ~3 for unpadded_size, _ in records)
    block_start -= blocks_len

    # Iterate over all blocks and add the correct block header CRC32
    for unpadded_size, _ in records:
        fh.seek(block_start)

        block_header = fh.read(1)
        block_header_size = (block_header[0] + 1) * 4
        block_header += fh.read(block_header_size - 1)
        repaired.add(fh.tell() - 4, _crc32(block_header[:-4]))

        block_start += (unpadded_size + 3) & ~3

    return repaired


def _mbi(data: bytes) -> tuple[int, int]:
    value = 0
    for size, byte in enumerate(data):
        value |= (byte & 0x7F) << (size * 7)
        if not byte & 0x80:
            return size + 1, value
    raise ValueError("Invalid mbi")


def _crc32(data: bytes) -> bytes:
    return int.to_bytes(crc32(data), 4, "little")


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
    """Attempt to parse the config FortiOS version to a readable format

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


def decrypt_password(b64_ciphertext: str) -> str:
    """Decrypt FortiOS version 6 and 7 encrypted secrets"""

    if b64_ciphertext[0:3] in ["SH2", "AK1"]:
        raise ValueError("Password is a hash (SHA-256 or SHA-1) and cannot be decrypted.")

    ciphertext = b64decode(b64_ciphertext)
    iv = ciphertext[0:4] + b"\x00" * 12
    key = b"Mary had a littl"
    cipher = AES.new(key, iv=iv, mode=AES.MODE_CBC)
    plaintext = cipher.decrypt(ciphertext[4:])
    return plaintext.split(b"\x00", 1)[0].decode()


def translate_timezone(timezone_num: str) -> str:
    """Translate a FortiOS timezone number to IANA TZ

    Resources:
        - https://<fortios>/ng/system/settings
    """

    TZ_MAP = {
        "01": "Etc/GMT+11",  # (GMT-11:00) Midway Island, Samoa
        "02": "Pacific/Honolulu",  # (GMT-10:00) Hawaii
        "03": "America/Anchorage",  # (GMT-9:00) Alaska
        "04": "America/Los_Angeles",  # (GMT-8:00) Pacific Time (US & Canada)
        "05": "America/Phoenix",  # (GMT-7:00) Arizona
        "81": "America/Chihuahua",  # (GMT-7:00) Baja California Sur, Chihuahua
        "06": "America/Denver",  # (GMT-7:00) Mountain Time (US & Canada)
        "07": "America/Guatemala",  # (GMT-6:00) Central America
        "08": "America/Chicago",  # (GMT-6:00) Central Time (US & Canada)
        "09": "America/Mexico_City",  # (GMT-6:00) Mexico City
        "10": "America/Regina",  # (GMT-6:00) Saskatchewan
        "11": "America/Bogota",  # (GMT-5:00) Bogota, Lima,Quito
        "12": "America/New_York",  # (GMT-5:00) Eastern Time (US & Canada)
        "13": "America/Indianapolis",  # (GMT-5:00) Indiana (East)
        "74": "America/Caracas",  # (GMT-4:00) Caracas
        "14": "America/Halifax",  # (GMT-4:00) Atlantic Time (Canada)
        "77": "Etc/GMT+4",  # (GMT-4:00) Georgetown
        "15": "America/La_Paz",  # (GMT-4:00) La Paz
        "87": "America/Asuncion",  # (GMT-4:00) Paraguay
        "16": "America/Santiago",  # (GMT-3:00) Santiago
        "17": "America/St_Johns",  # (GMT-3:30) Newfoundland
        "18": "America/Sao_Paulo",  # (GMT-3:00) Brasilia
        "19": "America/Buenos_Aires",  # (GMT-3:00) Buenos Aires
        "20": "America/Godthab",  # (GMT-3:00) Nuuk (Greenland)
        "75": "America/Montevideo",  # (GMT-3:00) Uruguay
        "21": "Etc/GMT+2",  # (GMT-2:00) Mid-Atlantic
        "22": "Atlantic/Azores",  # (GMT-1:00) Azores
        "23": "Atlantic/Cape_Verde",  # (GMT-1:00) Cape Verde Is.
        "24": "Atlantic/Reykjavik",  # (GMT) Monrovia
        "80": "Europe/London",  # (GMT) Greenwich Mean Time
        "79": "Africa/Casablanca",  # (GMT) Casablanca
        "25": "Etc/UTC",  # (GMT) Dublin, Edinburgh, Lisbon, London, Canary Is.
        "26": "Europe/Berlin",  # (GMT+1:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna
        "27": "Europe/Budapest",  # (GMT+1:00) Belgrade, Bratislava, Budapest, Ljubljana, Prague
        "28": "Europe/Paris",  # (GMT+1:00) Brussels, Copenhagen, Madrid, Paris
        "78": "Africa/Windhoek",  # (GMT+1:00) Namibia
        "29": "Europe/Warsaw",  # (GMT+1:00) Sarajevo, Skopje, Warsaw, Zagreb
        "30": "Africa/Lagos",  # (GMT+1:00) West Central Africa
        "31": "Europe/Kiev",  # (GMT+2:00) Athens, Sofia, Vilnius
        "32": "Europe/Bucharest",  # (GMT+2:00) Bucharest
        "33": "Africa/Cairo",  # (GMT+2:00) Cairo
        "34": "Africa/Johannesburg",  # (GMT+2:00) Harare, Pretoria
        "35": "Europe/Helsinki",  # (GMT+2:00) Helsinki, Riga, Tallinn
        "36": "Asia/Jerusalem",  # (GMT+2:00) Jerusalem
        "37": "Asia/Baghdad",  # (GMT+3:00) Baghdad
        "38": "Asia/Riyadh",  # (GMT+3:00) Kuwait, Riyadh
        "83": "Europe/Moscow",  # (GMT+3:00) Moscow
        "84": "Europe/Minsk",  # (GMT+3:00) Minsk
        "40": "Africa/Nairobi",  # (GMT+3:00) Nairobi
        "85": "Europe/Istanbul",  # (GMT+3:00) Istanbul
        "41": "Asia/Tehran",  # (GMT+3:30) Tehran
        "42": "Asia/Dubai",  # (GMT+4:00) Abu Dhabi, Muscat
        "43": "Asia/Baku",  # (GMT+4:00) Baku
        "39": "Europe/Volgograd",  # (GMT+3:00) St. Petersburg, Volgograd
        "44": "Asia/Kabul",  # (GMT+4:30) Kabul
        "46": "Asia/Karachi",  # (GMT+5:00) Islamabad, Karachi, Tashkent
        "47": "Asia/Calcutta",  # (GMT+5:30) Kolkata, Chennai, Mumbai, New Delhi
        "51": "Asia/Colombo",  # (GMT+5:30) Sri Jayawardenepara
    }

    return TZ_MAP.get(timezone_num, timezone_num)
