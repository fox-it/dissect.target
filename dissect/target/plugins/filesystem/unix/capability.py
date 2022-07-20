import struct
from enum import IntEnum
from io import BytesIO

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export


CapabilityRecord = TargetRecordDescriptor(
    "filesystem/unix/capability",
    [
        ("record", "record"),
        ("string[]", "permitted"),
        ("string[]", "inheritable"),
        ("boolean", "effective"),
        ("uint32", "rootid"),
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

    def check_compatible(self):
        return self.target.has_function("walkfs") and self.target.os != "windows"

    @export(record=CapabilityRecord)
    def capability_binaries(self):
        """Find all files that have capabilities set."""
        for entry, record in self.target.walkfs_ext():
            try:
                attrs = entry.get().lattr()
            except Exception:
                self.target.log.exception("Failed to get attrs for entry %s", entry)
                continue

            for attr in attrs:
                if attr.name != "security.capability":
                    continue

                buf = BytesIO(attr.value)

                # Reference: https://github.com/torvalds/linux/blob/master/include/uapi/linux/capability.h
                # The struct is small enough we can just use struct
                magic_etc = struct.unpack("<I", buf.read(4))[0]
                cap_revision = magic_etc & VFS_CAP_REVISION_MASK

                permitted_caps = []
                inheritable_caps = []
                rootid = None

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
                    self.target.log.error("Unexpected capability revision: %s", entry)
                    continue

                if data_len != len(attr.value):
                    self.target.log.error("Unexpected capability length: %s", entry)
                    continue

                for _ in range(num_caps):
                    permitted_val, inheritable_val = struct.unpack("<2I", buf.read(8))
                    permitted_caps.append(permitted_val)
                    inheritable_caps.append(inheritable_val)

                if cap_revision == VFS_CAP_REVISION_3:
                    rootid = struct.unpack("<I", buf.read(4))[0]

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

                yield CapabilityRecord(
                    record=record,
                    permitted=permitted,
                    inheritable=inheritable,
                    effective=magic_etc & VFS_CAP_FLAGS_EFFECTIVE != 0,
                    rootid=rootid,
                    _target=self.target,
                )
