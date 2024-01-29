import tempfile
from io import BytesIO
from pathlib import Path
from uuid import UUID

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix._os import parse_fstab
from dissect.target.target import Target

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
"""  # noqa


def test_parse_fstab(tmp_path):
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
    }


@pytest.mark.parametrize(
    "path, expected_hostname, expected_domain, file_content",
    [
        ("/etc/hostname", "myhost", "mydomain.com", "myhost.mydomain.com"),
        ("/etc/HOSTNAME", "myhost", "mydomain.com", "myhost.mydomain.com"),
        (
            "/etc/sysconfig/network",
            "myhost",
            "mydomain.com",
            "NETWORKING=NO\nHOSTNAME=myhost.mydomain.com\nGATEWAY=192.168.1.1",
        ),
        ("/etc/hostname", "myhost", None, "myhost"),
        ("/etc/sysconfig/network", "myhost", None, "NETWORKING=NO\nHOSTNAME=myhost\nGATEWAY=192.168.1.1"),
        ("/not_a_valid_hostname_path", None, None, ""),
        ("/etc/hostname", None, None, ""),
        ("/etc/sysconfig/network", None, None, ""),
    ],
)
def test__parse_hostname_string(
    target_unix: Target,
    fs_unix: VirtualFilesystem,
    path: Path,
    expected_hostname: str,
    expected_domain: str,
    file_content: str,
) -> None:
    fs_unix.map_file_fh(path, BytesIO(file_content.encode("ascii")))

    hostname_dict = target_unix._os._parse_hostname_string()

    assert hostname_dict["hostname"] == expected_hostname
    assert hostname_dict["domain"] == expected_domain
