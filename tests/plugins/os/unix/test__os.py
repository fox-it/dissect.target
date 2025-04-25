from __future__ import annotations

import tempfile
from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch
from uuid import UUID

import pytest
from flow.record.fieldtypes import posix_path

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix._os import UnixPlugin, parse_fstab
from dissect.target.target import Target

if TYPE_CHECKING:
    from pathlib import Path

FSTAB_CONTENT = """
# /etc/fstab: static file system information.
#
# Use 'blkid' to print the universally unique identifier for a
# device; this may be used with UUID= as a more robust way to name devices
# that works even if disks are added and removed. See fstab(5).
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>

proc                                      /proc        proc    nodev,noexec,nosuid 0    0

UUID=563f929e-ab4b-4741-b0f4-e3843c9a7a6a /            ext4    defaults,discard    0    0

UUID=5d1f1508-069b-4274-9bfa-ae2bf7ffb5e0 /home        ext4    defaults            0    2

UUID=be0afdc6-10bb-4744-a71c-02e0e2812160 none         swap    sw                  0    0

/dev/mapper/vgubuntu-swap_1               none         swap    sw                  0   0

UUID=28a25297-9825-4f87-ac41-f9c20cd5db4f /boot        ext4    defaults            0    2

UUID=F631-BECA                            /boot/efi    vfat    defaults,discard,umask=0077   0    0

/dev/disk/cloud/azure_resource-part1      /mnt         auto    defaults,nofail,x-systemd.requires=cloud-init.service,comment=cloudconfig   0   2

/dev/mapper/vg--main-lv--var              /var         auto    default             0    2

/dev/vg-main/lv-data                      /data        auto    default             0    2

/dev/disk/by-uuid/af0b9707-0945-499a-a37d-4da23d8dd245 /moredata auto default      0    2

LABEL=foo                                 /foo         auto    default             0    2

localhost:/home/user/nfstest              /mnt/nfs     nfs     ro                  0    0
"""  # noqa


def test_parse_fstab(tmp_path: Path) -> None:
    with tempfile.NamedTemporaryFile(dir=tmp_path, delete=False) as tf:
        tf.write(FSTAB_CONTENT.encode("ascii"))
        tf.close()

        fs = VirtualFilesystem()
        fs.map_file("/etc/fstab", tf.name)

        records = list(parse_fstab(fs.path("/etc/fstab")))

    # 11 input records minus
    #   2 unsupported mount devices (proc, /dev/disk/cloud/azure_resource-part1)
    #   2 swap partitions
    #   1 root partition
    # = 6 expected results

    assert set(records) == {
        (UUID("5d1f1508-069b-4274-9bfa-ae2bf7ffb5e0"), None, "/home", "ext4", "defaults"),
        (UUID("28a25297-9825-4f87-ac41-f9c20cd5db4f"), None, "/boot", "ext4", "defaults"),
        (UUID("af0b9707-0945-499a-a37d-4da23d8dd245"), None, "/moredata", "auto", "default"),
        ("F631-BECA", None, "/boot/efi", "vfat", "defaults,discard,umask=0077"),
        (None, "vg--main-lv--var", "/var", "auto", "default"),
        (None, "vg--main-lv--data", "/data", "auto", "default"),
        (None, "foo", "/foo", "auto", "default"),
        ("localhost", "/home/user/nfstest", "/mnt/nfs", "nfs", "ro"),
    }


def test_mount_volume_name_regression(fs_unix: VirtualFilesystem) -> None:
    mock_fs = Mock()
    mock_vol = Mock()

    mock_vol.name = "test-volume"

    mock_fs.__type__ = "ext"
    mock_fs.extfs.volume_name = "ext-volume"
    mock_fs.volume = mock_vol
    mock_fs.exists.return_value = False

    for expected_volume_name in ["test-volume", "ext-volume"]:
        with patch(
            "dissect.target.plugins.os.unix._os.parse_fstab",
            return_value=[(None, expected_volume_name, "/mnt", "auto", "default")],
        ):
            target = Target()
            target.filesystems.add(mock_fs)
            UnixPlugin.create(target, fs_unix)

            assert target.fs.mounts["/mnt"] == mock_fs


@pytest.mark.parametrize(
    ("hostname_content", "hosts_content", "expected_hostname", "expected_domain"),
    [
        (b"", b"", "localhost", None),
        (b"", b"127.0.0.1 mydomain", "mydomain", "mydomain"),
        (b"", b"127.0.0.1 localhost", "localhost", None),
        (b"hostname", b"127.0.0.1 localhost\n::1 ip6-localhost", "hostname", None),
        (b"hostname.example.internal", b"127.0.0.1 localhost\n::1 ip6-localhost", "hostname", "example.internal"),
        (b"myhost", b"", "myhost", None),
        (b"myhost.mydomain", b"", "myhost", "mydomain"),
        (b"myhost", b"127.0.0.1 mydomain", "myhost", "mydomain"),
        (b"myhost.mydomain", b"127.0.0.1 localhost", "myhost", "mydomain"),
        (b"myhost.localhost", b"127.0.0.1 mydomain", "myhost", "mydomain"),
        (b"myhost.mycoolerdomain", b"127.0.0.1 mydomain", "myhost", "mycoolerdomain"),
        (b"localhost.mycoolerdomain", b"127.0.0.1 mydomain", "localhost", "mycoolerdomain"),
        (b"localhost.mycoolerdomain", b"127.0.0.1 localhost", "localhost", "mycoolerdomain"),
    ],
)
def test_parse_domain(
    target_unix: Target,
    fs_unix: VirtualFilesystem,
    hostname_content: bytes,
    hosts_content: bytes,
    expected_domain: str,
    expected_hostname: str,
) -> None:
    fs_unix.map_file_fh("/etc/hostname", BytesIO(hostname_content))
    fs_unix.map_file_fh("/etc/hosts", BytesIO(hosts_content))
    target_unix.add_plugin(UnixPlugin)

    assert target_unix.hostname == expected_hostname, (
        f"Expected hostname {expected_hostname!r} but got {target_unix.hostname!r}"
    )
    assert target_unix.domain == expected_domain, f"Expected domain {expected_domain!r} but got {target_unix.domain!r}"


@pytest.mark.parametrize(
    ("path", "expected_hostname", "expected_domain", "file_content"),
    [
        ("/etc/hostname", "myhost", "mydomain.com", b"myhost.mydomain.com"),
        ("/etc/HOSTNAME", "myhost", "mydomain.com", b"myhost.mydomain.com"),
        (
            "/etc/sysconfig/network",
            "myhost",
            "mydomain.com",
            b"NETWORKING=NO\nHOSTNAME=myhost.mydomain.com\nGATEWAY=192.168.1.1",
        ),
        ("/etc/hostname", "myhost", None, b"myhost"),
        ("/etc/sysconfig/network", "myhost", None, b"NETWORKING=NO\nHOSTNAME=myhost\nGATEWAY=192.168.1.1"),
        ("/not_a_valid_hostname_path", None, None, b""),
        ("/etc/hostname", None, None, b""),
        ("/etc/sysconfig/network", None, None, b""),
        ("/proc/sys/kernel/hostname", "myhost", None, b"myhost"),
    ],
)
def test_parse_hostname_string(
    target_unix: Target,
    fs_unix: VirtualFilesystem,
    path: Path,
    expected_hostname: str | None,
    expected_domain: str | None,
    file_content: str,
) -> None:
    fs_unix.map_file_fh(path, BytesIO(file_content))

    hostname, domain = target_unix._os._parse_hostname_string()

    assert hostname == expected_hostname, f"Expected hostname {expected_hostname!r} but got {hostname!r}"
    assert domain == expected_domain, f"Expected domain {expected_domain!r} but got {domain!r}"


def test_users(target_unix_users: Target) -> None:
    users = list(target_unix_users.users())

    assert len(users) == 3

    assert users[0].name == "root"
    assert users[0].uid == 0
    assert users[0].gid == 0
    assert users[0].home == posix_path("/root")
    assert users[0].shell == "/bin/bash"

    assert users[1].name == "user"
    assert users[1].uid == 1000
    assert users[1].gid == 1000
    assert users[1].home == posix_path("/home/user")
    assert users[1].shell == "/bin/bash"

    assert users[2].name == "+@ngtest"
    assert users[2].uid is None
    assert users[2].gid is None
    assert users[2].home == posix_path("")
    assert users[2].shell == ""


@pytest.mark.parametrize(
    ("expected_arch", "elf_buf"),
    [
        # https://launchpad.net/ubuntu/+source/coreutils/9.4-3.1ubuntu1
        ("x86_64-unix", "7f454c4602010100000000000000000003003e0001000000a06d000000000000"),  # amd64
        ("aarch64-unix", "7f454c460201010000000000000000000300b70001000000405e000000000000"),  # arm64
        ("aarch32-unix", "7f454c4601010100000000000000000003002800010000001d40000034000000"),  # armhf
        ("x86_32-unix", "7f454c460101010000000000000000000300030001000000e042000034000000"),  # i386
        ("powerpc64-unix", "7f454c4602010100000000000000000003001500010000007470000000000000"),  # ppc64el
        ("riscv64-unix", "7f454c460201010000000000000000000300f30001000000685a000000000000"),  # riscv64
    ],
)
def test_architecture(target_unix: Target, fs_unix: VirtualFilesystem, expected_arch: str, elf_buf: str) -> None:
    """Test if we correctly parse unix architecture."""
    fs_unix.map_file_fh("/bin/ls", BytesIO(bytes.fromhex(elf_buf)))
    assert target_unix.architecture == expected_arch
