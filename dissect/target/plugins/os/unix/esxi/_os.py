from __future__ import annotations

import gzip
import json
import lzma
import struct
import subprocess
from configparser import ConfigParser
from configparser import Error as ConfigParserError
from io import BytesIO
from typing import TYPE_CHECKING, Any, BinaryIO, TextIO

from defusedxml import ElementTree
from dissect.hypervisor.util import vmtar
from dissect.sql import sqlite3

from dissect.target.filesystems.nfs import NfsFilesystem
from dissect.target.helpers.sunrpc import client
from dissect.target.helpers.sunrpc.client import LocalPortPolicy

try:
    from dissect.hypervisor.util.envelope import (
        HAS_PYCRYPTODOME,
        HAS_PYSTANDALONE,
        Envelope,
        KeyStore,
    )

    HAS_ENVELOPE = HAS_PYCRYPTODOME or HAS_PYSTANDALONE
except ImportError:
    HAS_ENVELOPE = False

from dissect.target.filesystems import tar
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import OperatingSystem, arg, export, internal
from dissect.target.plugins.os.unix._os import UnixPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem, VirtualFilesystem
    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.target import Target

VirtualMachineRecord = TargetRecordDescriptor(
    "esxi/vm",
    [
        ("path", "path"),
    ],
)


class ESXiPlugin(UnixPlugin):
    """ESXi OS plugin

    ESXi partitioning varies between versions. Generally, specific partition numbers have special meaning.

    The following is a list of known partition numbers:
        1: EFI boot
        5: BOOTBANK1
        6: BOOTBANK2
        7: vmkcore (ESXi 6), OSDATA / LOCKER (ESXi 7)
        8: store (ESXi 6), HDD VMFS datastore (ESXi 7)
        9: vmkcore (ESXi 6)
    """

    def __init__(self, target: Target):
        super().__init__(target)
        self._config = None
        self._configstore = None

        esx_conf = target.fs.path("/etc/vmware/esx.conf")
        if esx_conf.exists():
            self._config = parse_esx_conf(esx_conf.open("rt", encoding="utf-8"))

        # ESXi 7 introduced the configstore
        # It's made available at /etc/vmware/configstore/current-store-1 during boot, but stored at
        # the path used below in local.tgz
        configstore = target.fs.path("/var/lib/vmware/configstore/backup/current-store-1")
        if configstore.exists():
            self._configstore = parse_config_store(configstore.open())
            self._mount_nfs_shares()
        else:
            self.target.log.warning(
                "No configstore found, some functionality may not work (such as mounting NFS shares)"
            )

    def _cfg(self, path: str) -> str | None:
        if not self._config:
            self.target.log.warning("No ESXi config!")
            return None

        value_name = path.strip("/").split("/")[-1]
        obj = _traverse(path, self._config)

        if not value_name and obj:
            return obj

        return obj.get(value_name) if obj else None

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        bootbanks = [
            fs for fs in target.filesystems if fs.path("boot.cfg").exists() and list(fs.path("/").glob("*.v00"))
        ]

        cfgs = [(fs, parse_boot_cfg(fs.path("boot.cfg").open("rt"))) for fs in bootbanks]
        cfgs.sort(key=lambda pair: pair[1].get("updated", 0), reverse=True)

        return cfgs[0][0] if cfgs else None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> Self:
        cfg = parse_boot_cfg(sysvol.path("boot.cfg").open("rt"))

        # Mount all the visor tars in individual filesystem layers
        _mount_modules(target, sysvol, cfg)

        # Create a root layer for the "local state" filesystem
        # This stores persistent configuration data
        local_layer = target.fs.append_layer()

        # Mount the local.tgz to the local state layer
        _mount_local(target, local_layer)

        # Mount all other filesystems (VMFS, FAT16)
        _mount_filesystems(target, sysvol, cfg)

        obj = cls(target)

        # Symlink the /var/log directory to the correct destination (if available)
        _link_log_dir(target, cfg, obj)

        return obj

    @export(property=True)
    def hostname(self) -> str:
        if hostname := self._cfg("/adv/Misc/HostName"):
            return hostname.split(".", 1)[0]
        return "localhost"

    @export(property=True)
    def domain(self) -> str | None:
        if hostname := self._cfg("/adv/Misc/HostName"):
            return hostname.partition(".")[2]
        return None

    @export(property=True)
    def ips(self) -> list[str]:
        result = set()
        host_ip = self._cfg("/adv/Misc/HostIPAddr")
        mgmt_ip = self._cfg("/adv/Net/ManagementAddr")

        if host_ip:
            result.add(host_ip)
        if mgmt_ip:
            result.add(mgmt_ip)

        return list(result)

    @export(property=True)
    def version(self) -> str | None:
        boot_cfg = self.target.fs.path("/bootbank/boot.cfg")
        if not boot_cfg.exists():
            return None

        for line in boot_cfg.read_text().splitlines():
            if not line.startswith("build="):
                continue

            _, _, version = line.partition("=")
            return f"VMware ESXi {version.strip()}"
        return None

    @export(record=VirtualMachineRecord)
    def vm_inventory(self) -> Iterator[VirtualMachineRecord]:
        inv_file = self.target.fs.path("/etc/vmware/hostd/vmInventory.xml")
        if not inv_file.exists():
            return []

        root = ElementTree.fromstring(inv_file.read_text("utf-8"))
        for entry in root.iter("ConfigEntry"):
            yield VirtualMachineRecord(
                path=self.target.fs.path(entry.findtext("vmxCfgPath")),
                _target=self.target,
            )

    @export(output="none")
    @arg("path", help="config path")
    @arg("--as-json", action="store_true", help="format as json")
    def esxconf(self, path: str, as_json: bool) -> None:
        obj = self._cfg(path)

        if as_json:
            print(json.dumps(obj, indent=4, sort_keys=True))
        else:
            print(obj)

    @internal
    def configstore(self) -> dict[str, Any]:
        return self._configstore

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.ESXI.value

    def _mount_nfs_shares(self) -> None:
        """Mount NFS shares found in the configstore."""
        if not self._configstore:
            return

        nfs_shares: dict[str, Any] = self._configstore.get("esx", {}).get("storage", {}).get("nfs_v3_datastores", {})
        if not nfs_shares:
            if self._is_nfs_enabled:
                self.target.log.info("No NFS shares found in datastore")
            return

        for key, nfs_share in nfs_shares.items():
            # Parse the NFS share configuration
            user_value: dict[str, Any] = nfs_share.get("user_value", {})
            nfs_ip = user_value.get("hostname", "")
            volume_name = user_value.get("volume_name", "")
            remote_share = user_value.get("remote_share", "")
            if not nfs_ip or not volume_name or not remote_share:
                self.target.log.warning("Invalid NFS share configuration with key: %s", key)
                continue
            mount_point = f"/vmfs/volumes/{volume_name}"
            self._add_nfs(nfs_ip, remote_share, mount_point)

    def _add_nfs(self, nfs_ip: str, remote_share: str, mount_alias: str) -> None:
        """Mount NFS share to the target."""

        if not self._is_nfs_enabled:
            self._log_nfs_mount_disabled(nfs_ip, remote_share, mount_alias)
            return

        uuid = nfs_volume_uuid(nfs_ip, remote_share)
        mount_point = f"/vmfs/volumes/{uuid}"
        try:
            self.target.log.debug("Mounting NFS share %s at %s with alias %s", remote_share, mount_point, mount_alias)

            # On ESXi, there is typically only a single root user.
            # Besides, UnixPlugin::users does not work (see issue https://github.com/fox-it/dissect.target/issues/1093).
            # Moreover, socket rebinding is not implemented on ESXi.
            # Therefore, we try logging only as root. This implies that he NFS share has `no_root_squash` enabled.
            # According to the docs, ESxi mounts NFS shares using root privileges (https://www.vmware.com/docs/vmw-best-practices-running-nfs-vmware-vsphere)  # noqa: E501
            credentials = client.auth_unix("machine", 0, 0, [])
            nfs = NfsFilesystem.connect(nfs_ip, remote_share, credentials, LocalPortPolicy.PRIVILEGED)

            self.target.fs.mount(mount_point, nfs)
            self.target.fs.symlink(mount_point, mount_alias)
        except Exception as e:
            self.target.log.warning(
                "Failed to mount NFS share %s:%s at %s",
                nfs_ip,
                remote_share,
                mount_alias,
            )
            self.target.log.debug("", exc_info=e)


def _mount_modules(target: Target, sysvol: Filesystem, cfg: dict[str, str]) -> None:
    modules = [m.strip() for m in cfg["modules"].split("---")]

    for module in modules:
        module_path = sysvol.path(module)
        if not module_path.exists():
            target.log.warning("Non existent module: %s", module)
            continue

        tfs = None
        if module_path.name.endswith((".tar.gz", ".tgz")):
            tfs = tar.TarFilesystem(module_path.open())
        elif module_path.suffix.startswith(".v"):
            # Visor tar files are always gzipped
            cfile = gzip.GzipFile(fileobj=module_path.open())
            # Sometimes they are also xz compressed, check for XZ magic
            # NOTE: The XZ layer may also contain file signatures
            # Could be interesting to check.
            if cfile.peek(6)[:6] == b"\xfd7zXZ\x00":
                cfile = lzma.LZMAFile(cfile)  # noqa: SIM115

            tfs = tar.TarFilesystem(cfile, tarinfo=vmtar.VisorTarInfo)

        if tfs:
            target.fs.append_layer().mount("/", tfs)


def _mount_local(target: Target, local_layer: VirtualFilesystem) -> None:
    local_tgz = target.fs.path("local.tgz")
    local_tgz_ve = target.fs.path("local.tgz.ve")
    local_fs = None

    if local_tgz.exists():
        local_fs = tar.TarFilesystem(local_tgz.open())
    elif local_tgz_ve.exists():
        # In the case "encryption.info" does not exist, but ".#encryption.info" does
        encryption_info = next(target.fs.path("/").glob("*encryption.info"), None)
        if not local_tgz_ve.exists() or not encryption_info.exists():
            raise ValueError("Unable to find valid configuration archive")

        local_fs = _create_local_fs(target, local_tgz_ve, encryption_info)
    else:
        target.log.warning("No local.tgz or local.tgz.ve found, skipping local state")

    if local_fs:
        local_layer.mount("/", local_fs)


def _decrypt_envelope(local_tgz_ve: TargetPath, encryption_info: TargetPath) -> BinaryIO:
    """Decrypt ``local.tgz.ve`` ourselves with hard-coded keys."""
    envelope = Envelope(local_tgz_ve.open())
    keystore = KeyStore.from_text(encryption_info.read_text("utf-8"))
    return BytesIO(envelope.decrypt(keystore.key, aad=b"ESXConfiguration"))


def _decrypt_crypto_util(local_tgz_ve: TargetPath) -> BytesIO | None:
    """Decrypt ``local.tgz.ve`` using ESXi ``crypto-util``.

    We write to stdout, but this results in ``crypto-util`` exiting with a non-zero return code
    and stderr containing an I/O error message. The file does get properly decrypted, so we return
    ``None`` if there are no bytes in stdout which would indicate it actually failed.
    """

    result = subprocess.run(
        [
            "crypto-util",
            "envelope",
            "extract",
            "--aad",
            "ESXConfiguration",
            f"/{local_tgz_ve.as_posix()}",
            "-",
        ],
        capture_output=True,
    )

    if len(result.stdout) == 0:
        return None

    return BytesIO(result.stdout)


def _create_local_fs(target: Target, local_tgz_ve: TargetPath, encryption_info: TargetPath) -> tar.TarFilesystem | None:
    local_tgz = None

    if HAS_ENVELOPE:
        try:
            local_tgz = _decrypt_envelope(local_tgz_ve, encryption_info)
        except NotImplementedError:
            target.log.debug("Failed to decrypt %s, likely TPM encrypted", local_tgz_ve)
    else:
        target.log.debug("Skipping static decryption because of missing crypto module")

    if not local_tgz and target.name == "local":
        target.log.info(
            "local.tgz is encrypted but static decryption failed, attempting dynamic decryption using crypto-util"
        )
        local_tgz = _decrypt_crypto_util(local_tgz_ve)

        if local_tgz is None:
            target.log.warning("Dynamic decryption of %s failed", local_tgz_ve)
    else:
        target.log.warning("local.tgz is encrypted but static decryption failed and no dynamic decryption available!")

    if local_tgz:
        return tar.TarFilesystem(local_tgz)
    return None


def _mount_filesystems(target: Target, sysvol: Filesystem, cfg: dict[str, str]) -> None:
    version = cfg["build"]

    osdata_fs = None
    locker_fs = None
    for fs in target.filesystems:
        if fs.__type__ == "fat":
            fs.volume.seek(512)
            magic, uuid1, uuid2, uuid3, uuid4 = struct.unpack("<16sIIH6s", fs.volume.read(32))
            if magic != b"VMWARE FAT16    ":
                continue

            fs_uuid = f"{uuid1:08x}-{uuid2:08x}-{uuid3:04x}-{uuid4.hex()}"
            target.fs.mount(f"/vmfs/volumes/{fs_uuid}", fs)
            if not fs.volume.name.startswith("part_"):  # dissect.target quirk
                target.fs.symlink(f"/vmfs/volumes/{fs_uuid}", f"/vmfs/volumes/{fs.volume.name}")

            # ESXi 7 relies on volume names
            # ESXi 6 uses volume numbers
            if fs.volume.name in ("BOOTBANK1", "BOOTBANK2") or (
                fs.volume.number
                in (
                    5,
                    6,
                )
                and fs.exists("boot.cfg")
            ):
                if fs is sysvol:
                    target.fs.symlink(f"/vmfs/volumes/{fs_uuid}", "/bootbank")
                else:
                    target.fs.symlink(f"/vmfs/volumes/{fs_uuid}", "/altbootbank")

            # /store == partition number 8
            if version and version[0] == "6" and fs.volume.number == 8:
                target.fs.symlink(f"/vmfs/volumes/{fs_uuid}", "/store")
                target.fs.symlink("/store", "/locker")

        elif fs.__type__ == "vmfs":
            target.fs.mount(f"/vmfs/volumes/{fs.vmfs.uuid}", fs)
            target.fs.symlink(f"/vmfs/volumes/{fs.vmfs.uuid}", f"/vmfs/volumes/{fs.vmfs.label}")

            if fs.volume.name in ("OSDATA", "LOCKER"):
                target.fs.symlink(
                    f"/vmfs/volumes/{fs.vmfs.uuid}",
                    f"/vmfs/volumes/{fs.volume.name}-{fs.vmfs.uuid}",
                )

                if fs.volume.name == "OSDATA":
                    osdata_fs = fs
                elif fs.volume.name == "LOCKER":
                    locker_fs = fs

    # Symlink /scratch from locker.conf
    # A path _should_ always be set here, even in default installs where it points to OSDATA
    # This file is confusingly called locker.conf
    locker_conf = target.fs.path("/etc/vmware/locker.conf")
    if locker_conf.exists():
        scratch_path = locker_conf.read_text().strip().partition(" ")[0]
        if scratch_path:
            target.fs.symlink(scratch_path, "/scratch")
        else:
            target.log.warning("Scratch path from locker.conf is empty?")
    else:
        target.log.warning("No locker.conf!")

    # Symlink /locker
    # This is marked as legacy in ESXi 7, so may need changing when ESXi 8 comes out
    # Apparently the order is: OSDATA partition -> LOCKER partition -> RAM disk
    # We can't support RAM disk so only check OSDATA and LOCKER
    if osdata_fs:
        target.fs.symlink(f"/vmfs/volumes/OSDATA-{osdata_fs.vmfs.uuid}", "/var/lib/vmware/osdata")
        target.fs.symlink("/var/lib/vmware/osdata/store", "/store")
        target.fs.symlink("/var/lib/vmware/osdata/locker", "/locker")

    elif locker_fs:
        target.fs.symlink(f"/vmfs/volumes/LOCKER-{locker_fs.vmfs.uuid}", "/locker")


def _link_log_dir(target: Target, cfg: dict[str, str], plugin_obj: ESXiPlugin) -> None:
    version = cfg["build"]

    # Don't really know how ESXi does this, but let's just take a shortcut for now
    log_dir = None
    if version and version[0] == "7":
        try:
            log_dir = plugin_obj._configstore["esx"]["syslog"]["global_settings"][""]["user_value"]["log_dir"]
        except KeyError:
            target.log.warning("Failed to read log_dir from configstore, falling back to /scratch/log")
            log_dir = "/scratch/log"
    elif version and version[0] == "6":
        vmsyslog_file = target.fs.path("/etc/vmsyslog.conf")
        if vmsyslog_file.exists():
            try:
                vmsyslog_conf = ConfigParser()
                vmsyslog_conf.read_string(vmsyslog_file.read_text())

                log_dir = vmsyslog_conf.get("vmsyslog", "logdir")
                if log_dir == "<none>":
                    log_dir = "/scratch/log"
            except ConfigParserError as e:
                target.log.warning(
                    "Failed to read log_dir from vmsyslog.conf, falling back to /scratch/log",
                    exc_info=e,
                )
                log_dir = "/scratch/log"

    if log_dir:
        target.fs.symlink(log_dir, "/var/log")


def parse_boot_cfg(fh: TextIO) -> dict[str, str]:
    cfg = {}
    for line in fh:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        key, _, value = line.partition("=")

        cfg[key.strip()] = value.strip()

    return cfg


def parse_esx_conf(fh: TextIO) -> dict[str, Any]:
    config = {}
    for line in fh:
        line = line.strip()
        if not line:
            continue

        key, _, value = line.partition("=")
        key = key.strip().strip("/")
        value = value.strip().strip('"')

        if value == "true":
            value = True
        elif value == "false":
            value = False
        elif value.isnumeric():
            value = int(value)

        value_name = key.split("/")[-1]
        obj = _traverse(key, config, create=True)
        obj[value_name] = value

    return config


def _traverse(path: str, obj: dict[str, Any], create: bool = False) -> dict[str, Any] | None:
    parts = path.strip("/").split("/")
    path_parts = parts[:-1]
    for part in path_parts:
        array_idx = None
        if part.endswith("]"):
            part, _, rest = part.partition("[")
            array_idx = rest.strip("]")

        if part not in obj:
            if create:
                obj[part] = {}
            else:
                return None

        obj = obj[part]
        if array_idx:
            if array_idx not in obj:
                if create:
                    obj[array_idx] = {}
                else:
                    return None
            obj = obj[array_idx]

    return obj


def parse_config_store(fh: BinaryIO) -> dict[str, Any]:
    db = sqlite3.SQLite3(fh)

    store = {}

    if table := db.table("Config"):
        for row in table.rows():
            component_name = row.Component
            config_group_name = row.ConfigGroup
            value_group_name = row.Name
            identifier_name = row.Identifier

            if component_name not in store:
                store[component_name] = {}
            component = store[component_name]

            if config_group_name not in component:
                component[config_group_name] = {}
            config_group = component[config_group_name]

            if value_group_name not in config_group:
                config_group[value_group_name] = {}
            value_group = config_group[value_group_name]

            if identifier_name not in value_group:
                value_group[identifier_name] = {}
            identifier = value_group[identifier_name]

            identifier["modified_time"] = row.ModifiedTime
            identifier["creation_time"] = row.CreationTime
            identifier["version"] = row.Version
            identifier["success"] = row.Success
            identifier["auto_conf_value"] = json.loads(row.AutoConfValue) if row.AutoConfValue else None
            identifier["user_value"] = json.loads(row.UserValue) if row.UserValue else None
            identifier["vital_value"] = json.loads(row.VitalValue) if row.VitalValue else None
            identifier["cached_value"] = json.loads(row.CachedValue) if row.CachedValue else None
            identifier["desired_value"] = json.loads(row.DesiredValue) if row.DesiredValue else None
            identifier["revision"] = row.Revision

    return store


def mix64(a: int, b: int, c: int) -> int:
    """
    Mixes three 64-bit values reversibly.
    """
    # Implement logical right shift by masking first
    a = (a - b - c) ^ ((c & 0xFFFFFFFFFFFFFFFF) >> 43)
    b = (b - c - a) ^ (a << 9)
    c = (c - a - b) ^ ((b & 0xFFFFFFFFFFFFFFFF) >> 8)
    a = (a - b - c) ^ ((c & 0xFFFFFFFFFFFFFFFF) >> 38)
    b = (b - c - a) ^ (a << 23)
    c = (c - a - b) ^ ((b & 0xFFFFFFFFFFFFFFFF) >> 5)
    a = (a - b - c) ^ ((c & 0xFFFFFFFFFFFFFFFF) >> 35)
    b = (b - c - a) ^ (a << 49)
    c = (c - a - b) ^ ((b & 0xFFFFFFFFFFFFFFFF) >> 11)
    a = (a - b - c) ^ ((c & 0xFFFFFFFFFFFFFFFF) >> 12)
    b = (b - c - a) ^ (a << 18)
    c = (c - a - b) ^ ((b & 0xFFFFFFFFFFFFFFFF) >> 22)
    # Normalize to 64 bits
    return a & 0xFFFFFFFFFFFFFFFF, b & 0xFFFFFFFFFFFFFFFF, c & 0xFFFFFFFFFFFFFFFF


def esxi_hash(key: bytes, level: int) -> int:
    """
    Hashes a variable-length key into a 64-bit value.

    This hash function is used in the ESXi kernel.
    It is an exact implementation of the hash3 function defined here: http://burtleburtle.net/bob/c/lookup8.c
    """
    a: int = level
    b: int = level
    c: int = 0x9E3779B97F4A7C13  # Golden ratio, arbitrary value
    bytes_left: int = len(key)
    i: int = 0

    # Process the key in 24-byte chunks
    while bytes_left >= 24:
        a += int.from_bytes(key[i : i + 8], "little")
        b += int.from_bytes(key[i + 8 : i + 16], "little")
        c += int.from_bytes(key[i + 16 : i + 24], "little")
        a, b, c = mix64(a, b, c)
        i += 24
        bytes_left -= 24

    # Handle the last 23 bytes
    c = c + len(key)
    if bytes_left > 0:
        for shift, byte in enumerate(key[i:]):
            if shift < 8:
                a += byte << (shift * 8)
            elif shift < 16:
                b += byte << ((shift - 8) * 8)
            else:
                # c takes 23 - 8 - 8 = 7 bytes (length is added to LSB)
                c += byte << ((shift - 15) * 8)

    _, _, c = mix64(a, b, c)
    return c


def nfs_volume_uuid(host: str, path: str) -> str:
    """Generate a UUID for an NFS volume based on the host and path.

    This is used to create a unique identifier for NFS volumes in ESXi.
    """

    h1 = esxi_hash(host.encode(), 42)  # 42 is starting value
    h2 = esxi_hash(path.encode(), h1)

    low, high = h2 & 0xFFFFFFFF, ((h2 >> 32) & 0xFFFFFFFF)
    return f"{low:8x}-{high:8x}"
