from unittest.mock import Mock

from dissect.target.filesystem import VirtualFile
from dissect.target.plugins.filesystem.unix.capability import CapabilityPlugin


def test_capability_plugin(target_unix, fs_unix):
    # Some fictional capability values
    xattr1 = Mock()
    xattr1.name = "security.capability"
    xattr1.value = bytes.fromhex("010000010020F00000F00F0F")

    xattr2 = Mock()
    xattr2.name = "security.capability"
    xattr2.value = bytes.fromhex("010000020020F00F00F00F00F00F00F00F0F0100")

    xattr3 = Mock()
    xattr3.name = "security.capability"
    xattr3.value = bytes.fromhex("000000030020000000000000000000000000000039050000")

    vfile1 = VirtualFile(fs_unix, "file", None)
    vfile1.lattr = Mock()
    vfile1.lattr.return_value = [xattr1]
    fs_unix.map_file_entry("/path/to/xattr1/file", vfile1)

    vfile2 = VirtualFile(fs_unix, "file", None)
    vfile2.lattr = Mock()
    vfile2.lattr.return_value = [xattr2]
    fs_unix.map_file_entry("/path/to/xattr2/file", vfile2)

    vfile3 = VirtualFile(fs_unix, "file", None)
    vfile3.lattr = Mock()
    vfile3.lattr.return_value = [xattr3]
    fs_unix.map_file_entry("/path/to/xattr3/file", vfile3)

    target_unix.add_plugin(CapabilityPlugin)

    results = list(target_unix.capability_binaries())
    assert len(results) == 3

    assert results[0].record.path == "/path/to/xattr1/file"
    assert results[0].permitted == [
        "CAP_NET_RAW",
        "CAP_SYS_PACCT",
        "CAP_SYS_ADMIN",
        "CAP_SYS_BOOT",
        "CAP_SYS_NICE",
    ]
    assert results[0].inheritable == [
        "CAP_NET_ADMIN",
        "CAP_NET_RAW",
        "CAP_IPC_LOCK",
        "CAP_IPC_OWNER",
        "CAP_SYS_MODULE",
        "CAP_SYS_RAWIO",
        "CAP_SYS_CHROOT",
        "CAP_SYS_PTRACE",
        "CAP_SYS_RESOURCE",
        "CAP_SYS_TIME",
        "CAP_SYS_TTY_CONFIG",
        "CAP_MKNOD",
    ]
    assert results[0].effective
    assert results[0].rootid is None

    assert results[1].record.path == "/path/to/xattr2/file"
    assert results[1].permitted == [
        "CAP_NET_RAW",
        "CAP_SYS_PACCT",
        "CAP_SYS_ADMIN",
        "CAP_SYS_BOOT",
        "CAP_SYS_NICE",
        "CAP_SYS_RESOURCE",
        "CAP_SYS_TIME",
        "CAP_SYS_TTY_CONFIG",
        "CAP_MKNOD",
        "CAP_BLOCK_SUSPEND",
        "CAP_AUDIT_READ",
        "CAP_PERFMON",
        "CAP_BPF",
        "CAP_CHECKPOINT_RESTORE",
    ]
    assert results[1].inheritable == [
        "CAP_NET_ADMIN",
        "CAP_NET_RAW",
        "CAP_IPC_LOCK",
        "CAP_IPC_OWNER",
        "CAP_SYS_MODULE",
        "CAP_SYS_RAWIO",
        "CAP_SYS_CHROOT",
        "CAP_SYS_PTRACE",
        "CAP_MAC_OVERRIDE",
        "CAP_MAC_ADMIN",
        "CAP_SYSLOG",
        "CAP_WAKE_ALARM",
        "CAP_CHECKPOINT_RESTORE",
    ]
    assert results[1].effective
    assert results[1].rootid is None

    assert results[2].record.path == "/path/to/xattr3/file"
    assert results[2].permitted == ["CAP_NET_RAW"]
    assert results[2].inheritable == []
    assert not results[2].effective
    assert results[2].rootid == 1337
