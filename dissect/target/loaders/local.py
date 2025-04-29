from __future__ import annotations

import ctypes
import platform
import re
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar

from dissect.util.stream import BufferedStream

from dissect.target import filesystem, volume
from dissect.target.containers.raw import RawContainer
from dissect.target.exceptions import LoaderError
from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.helpers.utils import parse_path_uri
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from collections.abc import Iterator
    from logging import Logger

    from dissect.target.target import Target

SOLARIS_DEV_DIR = Path("/dev/dsk")
SOLARIS_DRIVE_REGEX = re.compile(r".+d\d+$")

LINUX_DEV_DIR = Path("/dev")
LINUX_DRIVE_REGEX = re.compile(r"(([sh]|xv)d[a-z]$)|(fd\d+$)|(nvme\d+n\d+$)")
VOLATILE_LINUX_PATHS = [
    Path("/proc"),
    Path("/sys"),
]

ESXI_DEV_DIR = Path("/vmfs/devices/disks")

WINDOWS_ERROR_INSUFFICIENT_BUFFER = 0x7A
WINDOWS_DRIVE_FIXED = 3


class LocalLoader(Loader):
    """Load local filesystem."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, resolve=False)

    @staticmethod
    def detect(path: Path) -> bool:
        _, path_part, _ = parse_path_uri(path)
        return path_part == "local"

    def map(self, target: Target) -> None:
        os_name = _get_os_name()

        force_dirfs = "force-directory-fs" in target.path_query
        fallback_to_dirfs = "fallback-to-directory-fs" in target.path_query

        if os_name == "windows":
            map_windows_mounted_drives(target, force_dirfs=force_dirfs, fallback_to_dirfs=fallback_to_dirfs)
        else:
            if fallback_to_dirfs or force_dirfs:
                # Where windos does some sophisticated fallback, for other
                # operating systems we don't know anything yet about the
                # relation between disks and mount points.
                # Temporary solution until we support parsing of /proc/mounts
                # and can implement OS-specific DirectoryFS fallback /
                # enforcement.
                target.filesystems.add(DirectoryFilesystem(Path("/")))
            elif os_name == "linux":
                map_linux_drives(target)
            elif os_name == "sunos":
                map_solaris_drives(target)
            elif os_name == "vmkernel":
                map_esxi_drives(target)
            elif os_name in ["darwin", "osx", "macos"]:
                # There is currently no way to access raw disk devices in OS-X,
                # so we always do a simple DirectoryFilesystem fallback.
                target.filesystems.add(DirectoryFilesystem(Path("/")))
            else:
                raise LoaderError(f"Unsupported OS for local target: {os_name}")


def map_linux_drives(target: Target) -> None:
    """Map Linux raw disks and /proc and /sys.

    Iterate through /dev and match raw device names (not partitions).

    /proc and /sys are mounted if they exists, allowing access to volatile files.
    """
    for drive in LINUX_DEV_DIR.iterdir():
        if LINUX_DRIVE_REGEX.match(drive.name):
            _add_disk_as_raw_container_to_target(drive, target)

    # Volatile filesystems are not present when running on a local target's raw
    # disks, so they are explicitly mounted here.
    #
    # Note that when running on a local target using a directory fs (through
    # force-directory-fs or fallback-to-directory-fs), these filesystems are
    # already present as they are usually mounted on the local system.
    for volatile_path in VOLATILE_LINUX_PATHS:
        if volatile_path.exists():
            volatile_fs = DirectoryFilesystem(volatile_path)
            target.filesystems.add(volatile_fs)
            target.fs.mount(str(volatile_path), volatile_fs)


def map_solaris_drives(target: Target) -> None:
    """Map Solaris raw disks.

    Iterate through /dev/dsk and match raw device names (not slices or partitions).
    """
    for drive in SOLARIS_DEV_DIR.iterdir():
        if not SOLARIS_DRIVE_REGEX.match(drive.name):
            continue
        _add_disk_as_raw_container_to_target(drive, target)


def map_esxi_drives(target: Target) -> None:
    """Map ESXi raw disks.

    Get all devices from /vmfs/devices/disks/* (not partitions).
    """
    for drive in ESXI_DEV_DIR.glob("vml.*"):
        if ":" in drive.name:
            continue
        _add_disk_as_raw_container_to_target(drive, target)


def map_windows_drives(target: Target) -> None:
    """Map Windows drives by iterating physical drives.

    For each physical drive, load the partition table and volumes.
    If a drive is encrypted using Bitlocker, use the OS transparent
    device to access it instead.

    Using this method, we get the drive serial and partition offset (MBR),
    or partition GUID (GPT), which we need for regular drive mounting.

    With this method we should open every partition of every disk,
    instead of only mounted drives.
    """
    devices = _windows_get_devices()

    physicaldrives = [d for d in devices if d.startswith("PhysicalDrive")]
    for drive in physicaldrives:
        drivenum = drive.replace("PhysicalDrive", "")
        drivepath = f"\\\\.\\{drive}"
        drivesize = None

        try:
            drivesize = _windows_get_disk_size(drivepath)
        except Exception as e:
            target.log.debug("Error getting size for drive %s", drive, exc_info=e)

        disk = RawContainer(
            BufferedStream(
                open(drivepath, "rb"),  # noqa: PTH123, SIM115
                size=drivesize,
            )
        )

        disk.vs = volume.open(disk)
        for i, vol in enumerate(disk.vs.volumes):
            # Open the decrypted volume if we encounter Bitlocker
            if b"-FVE-FS-" in vol.read(512):
                # Partition numbers are 1 indexed
                partname = f"Harddisk{drivenum}Partition{i + 1}"
                vol.fh = BufferedStream(
                    open(f"\\\\.\\{partname}", "rb"),  # noqa: PTH123, SIM115
                    size=vol.size,
                )
            vol.seek(0)
        disk.seek(0)

        # Alternative solution is to match partition by offset/guid
        # https://gist.github.com/santa4nt/11068180
        # https://docs.microsoft.com/en-us/windows/desktop/api/fltuser/nf-fltuser-filtergetdosname

        target.disks.add(disk)


def _add_disk_as_raw_container_to_target(drive: Path, target: Target) -> None:
    try:
        fh = BufferedStream(drive.open("rb"))
        target.disks.add(RawContainer(fh))
    except Exception as e:
        target.log.warning("Unable to open drive: %s, skipped", drive)
        target.log.debug("", exc_info=e)


def _read_drive_letters() -> list[bytes]:
    # Get all logical drive letters
    drives_buf = ctypes.c_buffer(256)
    ctypes.windll.kernel32.GetLogicalDriveStringsA(256, drives_buf)

    return drives_buf.raw.rstrip(b"\x00").split(b"\x00")


def _get_windows_drive_volumes(log: Logger) -> Iterator[tuple[volume.Volume, bool, RawContainer | None, int | None]]:
    # Get the sysvol drive letter
    windir_buf = ctypes.c_buffer(256)
    ctypes.windll.kernel32.GetWindowsDirectoryA(windir_buf, 256)
    windrive = windir_buf.raw[:2].decode().lower()

    disk_map = {}

    for drive_letter in _read_drive_letters():
        drive_letter = drive_letter.rstrip(b"\\")
        # Check for fixed drives
        drive_type = ctypes.windll.kernel32.GetDriveTypeA(drive_letter)
        if drive_type != WINDOWS_DRIVE_FIXED:
            continue

        drive_letter = drive_letter.decode().lower()
        drive_path = f"\\\\.\\{drive_letter}"

        # Attempt to read from drive
        # If it fails, skip it
        try:
            log.debug("Trying to read from drive %s", drive_letter)
            drive_volume = volume.Volume(BufferedStream(open(drive_path, "rb")), None, 0, None, None, None)  # noqa: PTH123, SIM115
            drive_volume.seek(0)
            drive_volume.read(1024)
            drive_volume.seek(0)
        except Exception as e:
            log.debug("Error reading drive %s", drive_letter, exc_info=e)
            continue

        drive_volume.drive_letter = drive_letter

        try:
            extent_info = _windows_get_volume_disk_extents(drive_path)
        except Exception as e:
            log.debug("Failed to get volume disk extents: %s", drive_path, exc_info=e)
            extent_info = None

        if extent_info and extent_info.NumberOfDiskExtents == 1:
            extent = extent_info.Extents[0]
            disk_num = extent.DiskNumber

            # Set offset and size now that we know them
            drive_volume.offset = extent.StartingOffset
            drive_volume.size = extent.ExtentLength
            drive_volume.fh.size = extent.ExtentLength

            if disk_num not in disk_map:
                disk_path = f"\\\\.\\PhysicalDrive{disk_num}"

                # Check if drive can be accessed (skip emulated drives like RAM disks)
                if not _is_physical_drive(disk_path):
                    log.debug(
                        "Skipped drive %d from %s, not a physical drive (could be emulation or ram disk)",
                        disk_num,
                        drive_path,
                    )
                    continue

                try:
                    disk_size = _windows_get_disk_size(disk_path)
                except Exception as e:
                    log.debug("Error getting size for disk %s", disk_path, exc_info=e)
                    disk_size = None
                try:
                    disk = RawContainer(
                        BufferedStream(
                            open(disk_path, "rb"),  # noqa: PTH123, SIM115
                            size=disk_size,
                        )
                    )
                    disk_map[disk_num] = disk
                except Exception as e:
                    log.debug("Unable to open disk %d at %s, skipped", disk_num, disk_path, exc_info=e)
                    continue
                try:
                    disk.vs = volume.open(disk)
                except Exception as e:
                    log.debug("Failed to open volume system on disk %s", disk_path, exc_info=e)
                disk.seek(0)
            else:
                disk = disk_map[disk_num]

            if disk.vs:
                # Find the matching volume on the disk
                for v in disk.vs.volumes:
                    if v.offset == drive_volume.offset:
                        v.fh = drive_volume.fh
                        drive_volume = v
                        break
            else:
                # Opening a volume system failed, map the disk to the volume anyway
                drive_volume.disk = disk
        else:
            disk = None
            disk_num = None

        yield (drive_volume, drive_letter == windrive, disk, disk_num)


def map_windows_mounted_drives(target: Target, force_dirfs: bool = False, fallback_to_dirfs: bool = False) -> None:
    """Map Windows drives by their drive letter.

    For each drive (mounted) partition, determine if it's a fixed drive
    and if it's readable. If it is, add it as a volume to the target.

    Since we don't know the drive serial and other information, we
    already mount filesystems to drive letters (which we do know).

    Downside to this method is that we only open mounted volumes.
    Upside is that we can also open BDE/LDM/Storage space volumes.

    Some inspiration drawn from http://velisthoughts.blogspot.com/2012/02/enumerating-and-using-partitions-and.html
    """

    disks = {}
    for drive_volume, is_windrive, disk, disk_num in _get_windows_drive_volumes(target.log):
        if disk:
            disks[disk_num] = disk

        if not disk or not disk.vs:
            target.volumes.add(drive_volume)

        if is_windrive:
            continue

        if force_dirfs:
            drive_volume.fs = DirectoryFilesystem(Path(f"{drive_volume.drive_letter}:\\"))
        else:
            try:
                drive_volume.fs = filesystem.open(drive_volume)
            except Exception as e:  # a wide exception to catch all issues with the filesystem
                target.log.debug(
                    "Failed to open filesystem of drive %s (volume: %s)",
                    drive_volume.drive_letter,
                    drive_volume,
                    exc_info=e,
                )
                if fallback_to_dirfs:
                    drive_volume.fs = DirectoryFilesystem(Path(f"{drive_volume.drive_letter}:\\"))

        if drive_volume.fs and drive_volume.drive_letter:
            target.fs.mount(drive_volume.drive_letter, drive_volume.fs)

    # Add all the disks we found.
    # DiskCollection.apply() will add the volumes found within them.
    for disk_num in sorted(disks.keys()):
        target.disks.add(disks[disk_num])


@cache
def _windows_get_devices() -> list[str]:
    """Internal function to query all devices.

    https://www.virag.si/2010/02/enumerate-physical-drives-in-windows/
    """
    bufsize = 256
    devices_buf = ctypes.c_buffer(bufsize)
    return_size = 0

    while return_size == 0:
        return_size = ctypes.windll.kernel32.QueryDosDeviceA(None, devices_buf, bufsize)

        if return_size == 0:
            errcode = ctypes.windll.kernel32.GetLastError()
            if errcode == WINDOWS_ERROR_INSUFFICIENT_BUFFER:
                bufsize *= 2
                devices_buf = ctypes.c_buffer(bufsize)
                continue
            raise ValueError

    return [d.decode() for d in devices_buf.raw.rstrip(b"\x00").split(b"\x00")]


def _is_physical_drive(path: str) -> bool:
    path = path.replace("\\\\.\\", "")
    return path in _windows_get_devices()


def _windows_get_disk_size(path: str) -> int:
    geometry_ex = _windows_get_disk_geometry_ex(path)
    return geometry_ex.DiskSize


def _windows_get_disk_geometry_ex(path: str) -> ctypes.Structure:
    from ctypes import wintypes

    IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x700A0

    class DISK_GEOMETRY(ctypes.Structure):
        _fields_ = (
            ("Cylinders", wintypes.LARGE_INTEGER),
            ("MediaType", wintypes.BYTE),
            ("TracksPerCylinder", wintypes.DWORD),
            ("SectorsPerTrack", wintypes.DWORD),
            ("BytesPerSector", wintypes.DWORD),
        )

    class DISK_GEOMETRY_EX(ctypes.Structure):
        _fields_ = (
            ("Geometry", DISK_GEOMETRY),
            ("DiskSize", wintypes.LARGE_INTEGER),
            ("Data", wintypes.BYTE),
        )

    handle = _windows_createfile(path)
    try:
        status, res = _windows_ioctl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, DISK_GEOMETRY_EX)
    finally:
        _windows_closehandle(handle)

    if status == 0:
        err = ctypes.windll.kernel32.GetLastError()
        raise OSError(f"unable to execute IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, error: 0x{err:08x}")

    return res


def _windows_get_volume_disk_extents(path: str) -> ctypes.Structure:
    from ctypes import wintypes

    ERROR_MORE_DATA = 234
    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x560000

    class DISK_EXTENT(ctypes.Structure):
        _fields_ = (
            ("DiskNumber", wintypes.DWORD),
            ("StartingOffset", wintypes.LARGE_INTEGER),
            ("ExtentLength", wintypes.LARGE_INTEGER),
        )

    class VOLUME_DISK_EXTENTS(ctypes.Structure):
        _fields_ = (
            ("NumberOfDiskExtents", wintypes.DWORD),
            ("Extents", DISK_EXTENT * 1),
        )

    handle = _windows_createfile(path)
    try:
        status, res = _windows_ioctl(handle, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, VOLUME_DISK_EXTENTS)
    finally:
        _windows_closehandle(handle)

    if status == 0:
        err = ctypes.windll.kernel32.GetLastError()
        if err != ERROR_MORE_DATA:
            raise OSError(f"unable to execute IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, error: 0x{err:08x}")

    return res


def _windows_createfile(path: str) -> int:
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080

    handle = ctypes.windll.kernel32.CreateFileW(
        path,
        0,
        0,
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0,
    )

    if handle == -1:
        err = ctypes.windll.kernel32.GetLastError()
        raise OSError(f"unable to open handle to {path}, error: 0x{err:08x}")

    return handle


def _windows_closehandle(handle: int) -> None:
    ctypes.windll.kernel32.CloseHandle(handle)


T = TypeVar("T", bound=ctypes.Structure)


def _windows_ioctl(handle: int, ioctl: int, out_struct: type[T]) -> tuple[int, T]:
    # http://www.ioctls.net/
    from ctypes import wintypes

    out_inst = out_struct()
    bytes_returned = wintypes.DWORD(0)
    status = ctypes.windll.kernel32.DeviceIoControl(
        handle,
        ioctl,
        None,
        0,
        ctypes.pointer(out_inst),
        ctypes.sizeof(out_struct),
        ctypes.byref(bytes_returned),
        None,
    )

    return status, out_inst


def _get_os_name() -> str:
    return platform.system().lower()
