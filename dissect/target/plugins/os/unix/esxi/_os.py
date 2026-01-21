from __future__ import annotations

import struct
import subprocess
from configparser import ConfigParser
from configparser import Error as ConfigParserError
from io import BytesIO
from typing import TYPE_CHECKING, Any, BinaryIO, TextIO

from dissect.util.hash.jenkins import lookup8

from dissect.target.filesystems.nfs import NfsFilesystem
from dissect.target.filesystems.vmtar import VmtarFilesystem
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
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix._os import UnixPlugin

if TYPE_CHECKING:
    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem, VirtualFilesystem
    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.target import Target


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
        self._mount_nfs_shares()

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        # First handle 'simple' case where we have to deal with a live collection
        for fs in target.filesystems:
            if fs.path("/etc/vmware/esx.conf").exists():
                return fs

        bootbanks = [
            fs for fs in target.filesystems if fs.path("boot.cfg").exists() and list(fs.path("/").glob("*.v00"))
        ]

        cfgs = [(fs, parse_boot_cfg(fs.path("boot.cfg").open("rt"))) for fs in bootbanks]
        cfgs.sort(key=lambda pair: pair[1].get("updated", 0), reverse=True)

        return cfgs[0][0] if cfgs else None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> Self:
        if sysvol.path("/etc/vmware/esx.conf").exists():
            target.fs.mount("/", sysvol)
            return cls(target)

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
        if hostname := self.target.esxconf.get("/adv/Misc/HostName"):
            return hostname.split(".", 1)[0]
        return "localhost"

    @export(property=True)
    def domain(self) -> str | None:
        if hostname := self.target.esxconf.get("/adv/Misc/HostName"):
            return hostname.partition(".")[2]
        return None

    @export(property=True)
    def ips(self) -> list[str]:
        result = set()
        host_ip = self.target.esxconf.get("/adv/Misc/HostIPAddr")
        mgmt_ip = self.target.esxconf.get("/adv/Net/ManagementAddr")

        if host_ip:
            result.add(host_ip)
        if mgmt_ip:
            result.add(mgmt_ip)

        return list(result)

    @export(property=True)
    def version(self) -> str | None:
        boot_cfg = self.target.fs.path("/bootbank/boot.cfg")
        if not boot_cfg.exists():
            # Default to retrieve version, but without build number
            return self.target.esxconf.get("/resourceGroups/version")

        for line in boot_cfg.read_text().splitlines():
            if not line.startswith("build="):
                continue

            _, _, version = line.partition("=")
            return f"VMware ESXi {version.strip()}"
        return None

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.ESXI.value

    def _mount_nfs_shares(self) -> None:
        """Mount NFS shares found in the configstore."""
        if not self.target.has_function("configstore.get"):
            self.target.log.warning("No configstore found, unable to mount NFS shares")
            return

        nfs_shares: dict[str, Any] = (
            self.target.configstore.get("esx", {}).get("storage", {}).get("nfs_v3_datastores", {})
        )
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
            try:
                tfs = VmtarFilesystem(module_path.open())
            except Exception as e:
                target.log.warning("%s, skipping file %s", str(e), module_path)
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

    if local_tgz is None:
        if target.name != "local":
            target.log.warning(
                "local.tgz is encrypted but static decryption failed and no dynamic decryption available!"
            )
            return None

        target.log.info(
            "local.tgz is encrypted but static decryption failed, attempting dynamic decryption using crypto-util"
        )
        local_tgz = _decrypt_crypto_util(local_tgz_ve)

        if local_tgz is None:
            target.log.warning("Dynamic decryption of %s failed", local_tgz_ve)

    return tar.TarFilesystem(local_tgz) if local_tgz else None


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
            log_dir = target.configstore._configstore["esx"]["syslog"]["global_settings"][""]["user_value"]["log_dir"]
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


def nfs_volume_uuid(host: str, path: str) -> str:
    """Generate a UUID for an NFS volume based on the host and path.

    This is used to create a unique identifier for NFS volumes in ESXi.
    """

    h1 = lookup8(host.encode(), 42)  # 42 is starting value
    h2 = lookup8(path.encode(), h1)

    low, high = h2 & 0xFFFFFFFF, ((h2 >> 32) & 0xFFFFFFFF)
    return f"{low:8x}-{high:8x}"
