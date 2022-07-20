import logging
import re
import uuid
from struct import unpack
from typing import Generator, Tuple, Union

from dissect.target.exceptions import FileNotFoundError
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugin import OSPlugin, export

log = logging.getLogger(__name__)


class LinuxPlugin(OSPlugin):
    def __init__(self, target):
        super().__init__(target)

        self.add_mounts()

    @classmethod
    def detect(cls, target):
        for fs in target.filesystems:
            if fs.exists("/var") and fs.exists("/etc") and not fs.exists("/Library"):
                return fs

        return None

    @classmethod
    def create(cls, target, sysvol):
        target.fs.mount("/", sysvol)
        return cls(target)

    def add_mounts(self):
        fstab = self.target.fs.path("/etc/fstab")

        volumes_to_mount = [v for v in self.target.volumes if v.fs]

        for dev_id, volume_name, _, mount_point in parse_fstab(fstab, self.target.log):

            for volume in volumes_to_mount:
                fs_id = None
                last_mount = None

                if dev_id and volume.fs.__fstype__ == "xfs":
                    fs_id = volume.fs.xfs.uuid
                elif dev_id and volume.fs.__fstype__ == "extfs":
                    fs_id = volume.fs.extfs.uuid
                    last_mount = volume.fs.extfs.last_mount
                elif dev_id and volume.fs.__fstype__ == "fat":
                    fs_id = volume.fs.fatfs.volume_id

                if (
                    (fs_id and (fs_id == dev_id))
                    or (volume.name and (volume.name == volume_name))
                    or (last_mount and (last_mount == mount_point))
                ):
                    self.target.log.debug("Mounting %s at %s", volume, mount_point)
                    self.target.fs.mount(mount_point, volume.fs)

    def _hostname(self):
        hostname = None

        for path in ["/etc/hostname", "/etc/HOSTNAME"]:
            try:
                hostname = self.target.fs.path(path).open("rt").read().rstrip()
                break
            except FileNotFoundError:
                pass

        ips = []
        try:
            ips = self.ips
        except Exception:
            pass

        try:
            fh = self.target.fs.path("/etc/hosts").open("rt")

            for line in fh:
                if line.startswith("#"):
                    continue

                parts = re.split(r"\s+", line.strip())
                if parts[0] in ips:
                    hostname = parts[1]
                    break

                if parts[0] == "127.0.0.1" and "localhost" not in parts[1]:
                    hostname = parts[1]
                    break
        except FileNotFoundError:
            pass

        return hostname

    @export(property=True)
    def hostname(self):
        hostname = self._hostname()
        if hostname and "." in hostname:
            hostname = hostname.split(".")[0]
        return hostname

    @export(property=True)
    def domain(self):
        hostname = self._hostname()
        if hostname and "." in hostname:
            return hostname.split(".", 1)[1]
        return None

    @export(property=True)
    def ips(self):
        import configparser

        result = []

        try:
            for file_ in self.target.fs.path("/etc/sysconfig/network-scripts").glob("ifcfg-*"):
                if file_.name == "ifcfg-lo":
                    continue

                for line in file_.open("rt"):
                    key, _, value = line.strip().partition("=")
                    if key == "IPADDR":
                        result.append(value.strip('"'))
                        break

        except FileNotFoundError:
            pass

        if result:
            return result

        # Photon/Systemd
        try:
            for file_ in self.target.fs.path("/etc/systemd/network").glob("*.network"):
                conf = configparser.ConfigParser()
                conf.readfp(file_.open("rt"))

                ip = conf.get("Network", "address")
                if "/" in ip:
                    ip = ip.split("/")[0]
                result.append(ip)
        except FileNotFoundError:
            pass

        if result:
            return result

        # AppC
        try:
            fh = self.target.fs.path("/etc/sysconfig/ip.start").open("rt")
            for line in fh:
                p = line.strip().split(" ")
                if p[:3] == ["ip", "addr", "add"]:
                    result.append(p[3].split("/")[0])
        except FileNotFoundError:
            pass

        # netplan
        try:
            import yaml

            for file_ in self.target.fs.path("/etc/netplan").glob("*.yaml"):
                try:
                    obj = yaml.load(file_.open("rt"), Loader=yaml.FullLoader)
                    ethernets = obj["network"]["ethernets"]
                    for networks in ethernets.values():
                        for ip in networks["addresses"]:
                            result.append(ip.split("/")[0])
                except Exception:
                    continue
        except (FileNotFoundError, ImportError):
            pass

        return result

    @export(property=True)
    def version(self):
        dist_info = {}

        for path in ["/etc/os-release", "/usr/lib/os-release", "/etc/lsb-release"]:
            release_file = self.target.fs.path(path)
            if not release_file.exists():
                continue

            try:
                for line in release_file.open("rt"):
                    parts = line.strip().split("=", 1)
                    if len(parts) != 2:
                        continue

                    dist_info[parts[0].upper()] = parts[1].strip('"')
            except Exception:
                continue

        if dist_info:
            if "PRETTY_NAME" in dist_info:
                return dist_info["PRETTY_NAME"]

            if "DISTRIB_DESCRIPTION" in dist_info:
                return dist_info["DISTRIB_DESCRIPTION"]

        paths = ["/etc/fedora-release", "/etc/redhat-release", "/etc/SuSE-release"]

        for path in paths:
            file_ = self.target.fs.path(path)
            if not file_.exists():
                continue

            return file_.open("rt").readline().strip()

        return "Linux Unknown"

    @export(record=UnixUserRecord)
    def users(self):
        passwd = self.target.fs.path("/etc/passwd")
        if not passwd.exists():
            return

        for line in passwd.open("rt"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            pwent = line.split(":")
            yield UnixUserRecord(
                name=pwent[0],
                passwd=pwent[1],
                uid=pwent[2],
                gid=pwent[3],
                gecos=pwent[4],
                home=pwent[5],
                shell=pwent[6],
                _target=self.target,
            )

    @export(property=True)
    def architecture(self):
        """
        Returns a dict containing the architecture and bitness of the system

        Returns:
            Dict: arch: architecture, bitness: bits
        """

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
            0x3E: "x86-64",
            0xB7: "AArch64",
            0xF3: "RISC-V",
        }

        for fs in self.target.filesystems:
            if fs.exists("/bin/true"):
                fh = fs.open("/bin/true")
                fh.seek(4)
                bits = unpack("B", fh.read(1))[0]
                fh.seek(16)
                arch = unpack("H", fh.read(2))[0]

                return {"arch": arch_strings.get(arch), "bitness": 64 if bits == 2 else 32}

    @export(property=True)
    def os(self):
        return "linux"


class CentOSPlugin(LinuxPlugin):
    @classmethod
    def detect(cls, target):
        for fs in target.filesystems:
            if fs.exists("/etc/sysconfig/network-scripts"):
                return fs

        return None

    @export(property=True)
    def ips(self):
        r = []

        path = self.target.fs.path("/etc/sysconfig/network-scripts")
        for file_ in path.glob("ifcfg-*"):
            fh = file_.open("rt")

            d = {}
            for line in fh:
                p = line.strip().split("=", 1)
                if len(p) != 2:
                    continue
                k, v = p
                d[k.lower()] = v.strip('"').strip("'")
            fh.close()

            for k, v in d.items():
                if k.startswith("ipaddr"):
                    ip = v.split("/")[0]
                    if ip in ("127.0.0.1", "0.0.0.0"):
                        continue

                    r.append(ip)
        return r


class SuSEPlugin(LinuxPlugin):
    @classmethod
    def detect(cls, target):
        for fs in target.filesystems:
            if fs.exists("/etc/sysconfig/network"):
                return fs

        return None

    @export(property=True)
    def ips(self):
        r = []
        path = self.target.fs.path("/etc/sysconfig/network")
        for file_ in path.glob("ifcfg-*"):
            fh = file_.open("rt")

            d = {}
            for line in fh:
                p = line.strip().split("=", 1)
                if len(p) != 2:
                    continue
                k, v = p
                d[k.lower()] = v.strip('"').strip("'")
            fh.close()

            ip = d["ipaddr"].split("/")[0]
            if ip == "127.0.0.1":
                continue

            r.append(ip)
        return r


def parse_fstab(
    fstab: TargetPath,
    log: logging.Logger = log,
) -> Generator[Tuple[Union[uuid.UUID, str], str, str, str], None, None]:
    """
    Parse fstab file and return a generator that streams the details of entries,
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
