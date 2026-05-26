from __future__ import annotations

import ctypes
from typing import TypeVar

T = TypeVar("T", bound=ctypes.Structure)


def _windows_get_disk_size(path: str) -> int:
    """Get disk size from a Drive path. Must be used only on a Windows platform.

    Args:
        path: Drive path, e.g \\\\.\\PhysicalDrive0
    """
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


def _windows_createfile(path: str) -> int:
    """Open a file using the windows CreateFileW API."""
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
    """Close an Handle using windows CloseHandle API.

    Args:
        handle: file handle create dusing _windows_createfile.
    """
    ctypes.windll.kernel32.CloseHandle(handle)


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
