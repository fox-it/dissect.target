import zlib
from io import BytesIO

import pytest

from dissect.target.plugins.os.unix.linux.iveos._os import IvantiCorebootFile, IveOSPlugin
from tests._utils import absolute_path


def test_parse_version() -> None:
    version_file_text = """export DSREL_MAJOR=22
export DSREL_MINOR=7
export DSREL_MAINT=2
export DSREL_DATAVER=5812
export DSREL_PRODUCT=ive
export DSREL_COMPANY="Ivanti, Inc."
export DSREL_COMPANYKEY="Pulse Secure"
export DSREL_BUILDNUM=5367
export DSREL_COMMENT="R2.10"
    """
    parsed_version = IveOSPlugin.parse_version_file(BytesIO(version_file_text.encode()))

    assert parsed_version == "22.7R2.10"


def test_ivanti_decryption_aligned() -> None:
    decompressed_coreboot_blob = """
    30373037303139353834463443323030
    30303431454430303030303241333030
    30303031464630303030303030413633
    38453136463030303030303030303030
    30303030303030303030303033393030
    30303030303030303030303030303030
    30303030303230303030303030302e00
    30373037303139353834454430443030
    30303831454430303030303241333030
    30303031464630303030303030313633
    38453136463030303031373842433030
    30303030303030303030303033393030
    """
    key = bytes.fromhex("ec14f9fac57e45699a525475e316d2df")

    with absolute_path("_data/plugins/os/unix/linux/iveos/_os/coreboot-enc.bin").open("rb") as fh:
        decrypted_buf = IvantiCorebootFile(fh, key).read()

        assert decrypted_buf[:16].hex() == "1f8b0800f0168e630203dcfd0b5c54d5"

        zobj_2 = zlib.decompressobj(zlib.MAX_WBITS | 16)
        decompressed_buf = zobj_2.decompress(decrypted_buf)

        assert decompressed_buf[:192] == bytes.fromhex(decompressed_coreboot_blob)


def test_ivanti_decryption_unaligned() -> None:
    key = bytes.fromhex("ec14f9fac57e45699a525475e316d2df")

    with absolute_path("_data/plugins/os/unix/linux/iveos/_os/coreboot-enc.bin").open("rb") as fh:
        ivanti_fh = IvantiCorebootFile(fh, key)

        ivanti_fh.seek(0x707)

        assert ivanti_fh.read(16) == bytes.fromhex("7f008c3ffa03815e467f10d011e8df0e")


def test_parse_grub() -> None:
    grub_config = """menuentry "Current" {
set root=(hd0,3)
    linux /kernel system=B rootdelay=5 console=ttyS0,115200n8 console=tty0 vm_hv_type=VMware
    initrd /coreboot.img
}
menuentry "Rollback" {
set root=(hd0,2)
    linux /kernel system=A rootdelay=5 rollback console=ttyS0,115200n8 console=tty0 vm_hv_type=VMware
    initrd /coreboot.img
}
menuentry "Factory Reset" {
set root=(hd0,1)
    linux /kernel system=Z noconfirm rootdelay=5 console=ttyS0,115200n8 console=tty0 vm_hv_type=VMware
    initrd /coreboot.img
}
    """
    active, rollback, reset = IveOSPlugin.parse_grub_config(grub_config)

    assert active == "groupB"
    assert rollback == "groupA"
    assert reset == "groupZ"

    grub_config = """menuentry "Current" {
set root=(hd0,2)
    linux /kernel system=A rootdelay=5 console=ttyS0,115200n8 console=tty0 vm_hv_type=VMware
    initrd /coreboot.img
}
menuentry "Factory Reset" {
set root=(hd0,1)
    linux /kernel system=Z noconfirm rootdelay=5 console=ttyS0,115200n8 console=tty0 vm_hv_type=VMware
    initrd /coreboot.img
}
    """
    active, rollback, reset = IveOSPlugin.parse_grub_config(grub_config)

    assert active == "groupA"
    assert rollback is None
    assert reset == "groupZ"


def test_parse_grub_fail() -> None:
    grub_config = """menuentry "Current" {
set root=(hd0,3)
    linux /kernel system=A rootdelay=5 console=ttyS0,115200n8 console=tty0 vm_hv_type=VMware
    initrd /coreboot.img
}
menuentry "Current" {
set root=(hd0,2)
    linux /kernel system=B rootdelay=5 rollback console=ttyS0,115200n8 console=tty0 vm_hv_type=VMware
    initrd /coreboot.img
}
menuentry "Factory Reset" {
set root=(hd0,1)
    linux /kernel system=Z noconfirm rootdelay=5 console=ttyS0,115200n8 console=tty0 vm_hv_type=VMware
    initrd /coreboot.img
}
    """
    with pytest.raises(ValueError, match="Found multiple active installations for Current!"):
        IveOSPlugin.parse_grub_config(grub_config)
