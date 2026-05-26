from __future__ import annotations

import ctypes
from typing import TypeVar

T = TypeVar("T", bound=ctypes.Structure)


def _windows_get_disk_size(path: str) -> int:
    """Get disk size from a Drive path. Must be used only on a Windows platform.

    Args:
        path: Drive path, E.g \\\\.\\PhysicalDrive0
    """
    geometry_ex = _windows_get_disk_geometry_ex(path)
    return geometry_ex.DiskSize


def _windows_get_drive_size(path: str) -> int:
    """Retrieves the length of the specified disk, volume, or partition. Must be used only on a Windows platform.

    Args:
        path: Drive path, E.g `\\\\.\\PhysicalDrive0`, `\\\\.\\C:`
    """
    return _windows_disk_get_length_info(path)




"""
#define FILE_DEVICE_DISK                0x00000007
#define METHOD_BUFFERED                 0
#define IOCTL_DISK_BASE                 FILE_DEVICE_DISK
#define FILE_ANY_ACCESS                 0
#define FILE_READ_ACCESS          ( 0x0001 )    // file & pipe
#define IOCTL_DISK_GET_LENGTH_INFO          CTL_CODE(IOCTL_DISK_BASE, 0x0017, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_DISK_GET_DRIVE_GEOMETRY_EX    CTL_CODE(IOCTL_DISK_BASE, 0x0028, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

"""
def _windows_disk_get_length_info(path: str) -> int:
    """
    Call IOCTL_DISK_GET_LENGTH_INFO.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_disk_get_length_info
    """
    IOCTL_DISK_GET_LENGTH_INFO = 0x7405C
    from ctypes import wintypes

    class GET_LENGTH_INFORMATION(ctypes.Structure):
        _fields_ = (
            ("Length", wintypes.LARGE_INTEGER),
        )

    handle = _windows_createfile(path)
    try:
        status, res = _windows_ioctl(handle, IOCTL_DISK_GET_LENGTH_INFO, GET_LENGTH_INFORMATION)
    finally:
        _windows_closehandle(handle)

    if status == 0:
        err = ctypes.windll.kernel32.GetLastError()
        raise OSError(f"unable to execute IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, error: 0x{err:08x}")

    return res.Length


def _windows_get_disk_geometry_ex(path: str) -> ctypes.Structure:
    """Call IOCTL_DISK_GET_DRIVE_GEOMETRY_EX to retrieve size from the physical disk's geometry.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_disk_get_drive_geometry_ex
    """
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
