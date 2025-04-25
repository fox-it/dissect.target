from __future__ import annotations

from enum import IntEnum
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

CapabilityRecord = TargetRecordDescriptor(
    "filesystem/unix/capability",
    [
        ("datetime", "ts_mtime"),
        ("path", "path"),
        ("string[]", "permitted"),
        ("string[]", "inheritable"),
        ("boolean", "effective"),
        ("uint32", "root_id"),
    ],
)


VFS_CAP_REVISION_MASK = 0xFF000000
VFS_CAP_REVISION_SHIFT = 24
VFS_CAP_FLAGS_MASK = (~VFS_CAP_REVISION_MASK) & 0xFFFFFFFF
VFS_CAP_FLAGS_EFFECTIVE = 0x000001

VFS_CAP_REVISION_1 = 0x01000000
VFS_CAP_U32_1 = 1

VFS_CAP_REVISION_2 = 0x02000000
VFS_CAP_U32_2 = 2

VFS_CAP_REVISION_3 = 0x03000000
VFS_CAP_U32_3 = 2


class Capabilities(IntEnum):
    CAP_CHOWN = 0
    CAP_DAC_OVERRIDE = 1
    CAP_DAC_READ_SEARCH = 2
    CAP_FOWNER = 3
    CAP_FSETID = 4
    CAP_KILL = 5
    CAP_SETGID = 6
    CAP_SETUID = 7
    CAP_SETPCAP = 8
    CAP_LINUX_IMMUTABLE = 9
    CAP_NET_BIND_SERVICE = 10
    CAP_NET_BROADCAST = 11
    CAP_NET_ADMIN = 12
    CAP_NET_RAW = 13
    CAP_IPC_LOCK = 14
    CAP_IPC_OWNER = 15
    CAP_SYS_MODULE = 16
    CAP_SYS_RAWIO = 17
    CAP_SYS_CHROOT = 18
    CAP_SYS_PTRACE = 19
    CAP_SYS_PACCT = 20
    CAP_SYS_ADMIN = 21
    CAP_SYS_BOOT = 22
    CAP_SYS_NICE = 23
    CAP_SYS_RESOURCE = 24
    CAP_SYS_TIME = 25
    CAP_SYS_TTY_CONFIG = 26
    CAP_MKNOD = 27
    CAP_LEASE = 28
    CAP_AUDIT_WRITE = 29
    CAP_AUDIT_CONTROL = 30
    CAP_SETFCAP = 31
    CAP_MAC_OVERRIDE = 32
    CAP_MAC_ADMIN = 33
    CAP_SYSLOG = 34
    CAP_WAKE_ALARM = 35
    CAP_BLOCK_SUSPEND = 36
    CAP_AUDIT_READ = 37
    CAP_PERFMON = 38
    CAP_BPF = 39
    CAP_CHECKPOINT_RESTORE = 40


class CapabilityPlugin(Plugin):
    """Plugin to yield files with capabilites set."""

    def check_compatible(self) -> None:
        if not self.target.has_function("walkfs"):
            raise UnsupportedPluginError("Need walkfs plugin")

        if not any(fs.__type__ in ("extfs", "xfs") for fs in self.target.filesystems):
            raise UnsupportedPluginError("Capability plugin only works on EXT and XFS filesystems")

    @export(record=CapabilityRecord)
    def capability_binaries(self) -> Iterator[CapabilityRecord]:
        """Find all files that have capabilities set on files.

        Resources:
            - https://github.com/torvalds/linux/blob/master/include/uapi/linux/capability.h
        """

        for entry in self.target.fs.recurse("/"):
            if not entry.is_file() or entry.is_symlink():
                continue

            try:
                attrs = [attr for attr in entry.lattr() if attr.name == "security.capability"]
            except Exception as e:
                self.target.log.warning("Failed to get attrs for entry %s", entry)
                self.target.log.debug("", exc_info=e)
                continue

            for attr in attrs:
                try:
                    permitted, inheritable, effective, root_id = parse_attr(attr.value)
                except ValueError as e:
                    self.target.log.warning("Could not parse attributes for entry %s: %s", entry, str(e.value))
                    self.target.log.debug("", exc_info=e)

                yield CapabilityRecord(
                    ts_mtime=entry.lstat().st_mtime,
                    path=self.target.fs.path(entry.path),
                    permitted=permitted,
                    inheritable=inheritable,
                    effective=effective,
                    root_id=root_id,
                    _target=self.target,
                )


def parse_attr(attr: bytes) -> tuple[list[str], list[str], bool, int]:
    """Efficiently parse a Linux xattr capability struct.

    Returns:
        A tuple of permitted capability names, inheritable capability names, effective flag and ``root_id``.
    """
    buf = BytesIO(attr)

    # The struct is small enough we can just use int.from_bytes
    magic_etc = int.from_bytes(buf.read(4), "little")
    effective = magic_etc & VFS_CAP_FLAGS_EFFECTIVE != 0
    cap_revision = magic_etc & VFS_CAP_REVISION_MASK

    permitted_caps = []
    inheritable_caps = []
    root_id = None

    if cap_revision == VFS_CAP_REVISION_1:
        num_caps = VFS_CAP_U32_1
        data_len = (1 + 2 * VFS_CAP_U32_1) * 4

    elif cap_revision == VFS_CAP_REVISION_2:
        num_caps = VFS_CAP_U32_2
        data_len = (1 + 2 * VFS_CAP_U32_2) * 4

    elif cap_revision == VFS_CAP_REVISION_3:
        num_caps = VFS_CAP_U32_3
        data_len = (2 + 2 * VFS_CAP_U32_2) * 4

    else:
        raise ValueError(f"Unexpected capability revision '{cap_revision}'")

    if data_len != (actual_len := len(attr)):
        raise ValueError("Unexpected capability length (%s vs %s)", data_len, actual_len)

    for _ in range(num_caps):
        permitted_caps.append(int.from_bytes(buf.read(4), "little"))
        inheritable_caps.append(int.from_bytes(buf.read(4), "little"))

    if cap_revision == VFS_CAP_REVISION_3:
        root_id = int.from_bytes(buf.read(4), "little")

    permitted = []
    inheritable = []

    for capability in Capabilities:
        for caps, results in [(permitted_caps, permitted), (inheritable_caps, inheritable)]:
            # CAP_TO_INDEX
            cap_index = capability.value >> 5
            if cap_index >= len(caps):
                # We loop over all capabilities, but might only have a version 1 caps list
                continue

            if caps[cap_index] & (1 << (capability.value & 31)) != 0:
                results.append(capability.name)

    return permitted, inheritable, effective, root_id
