from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import patch

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugin import OperatingSystem
from dissect.target.plugins.os.unix.esxi._os import ESXiPlugin, _create_local_fs, _decrypt_crypto_util
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.target import Target


def test__create_tar_fs_no_envelope(target_linux: Target, fs_unix: VirtualFilesystem) -> None:
    with (
        patch("dissect.target.plugins.os.unix.esxi._os.HAS_ENVELOPE", False),
        patch("dissect.target.plugins.os.unix.esxi._os.tar") as mocked_tar,
        patch("dissect.target.plugins.os.unix.esxi._os._decrypt_crypto_util") as decrypt_func,
    ):
        target_linux._name = "local"
        _create_local_fs(target_linux, fs_unix.path("local.tgz.ve"), fs_unix.path("encryption.info"))

        decrypt_func.assert_called()
        mocked_tar.TarFilesystem.assert_called()


def test__create_tar_fs_envelope(target_linux: Target, fs_unix: VirtualFilesystem) -> None:
    with (
        patch("dissect.target.plugins.os.unix.esxi._os.HAS_ENVELOPE", True),
        patch("dissect.target.plugins.os.unix.esxi._os.tar") as mocked_tar,
        patch("dissect.target.plugins.os.unix.esxi._os._decrypt_envelope") as decrypt_func,
    ):
        _create_local_fs(target_linux, fs_unix.path("local.tgz.ve"), fs_unix.path("encryption.info"))

        decrypt_func.assert_called()
        mocked_tar.TarFilesystem.assert_called()


def test__create_tar_fs_failed_envelope(target_linux: Target, fs_unix: VirtualFilesystem) -> None:
    with (
        patch("dissect.target.plugins.os.unix.esxi._os.HAS_ENVELOPE", True),
        patch("dissect.target.plugins.os.unix.esxi._os.tar") as mocked_tar,
        patch("dissect.target.plugins.os.unix.esxi._os._decrypt_envelope", side_effect=[NotImplementedError]),
        patch("dissect.target.plugins.os.unix.esxi._os._decrypt_crypto_util") as decrypt_func,
    ):
        target_linux._name = "local"
        _create_local_fs(target_linux, fs_unix.path("local.tgz.ve"), fs_unix.path("encryption.info"))

        decrypt_func.assert_called()
        mocked_tar.TarFilesystem.assert_called()


def test__decrypt_crypto_not_local(target_linux: Target, fs_unix: VirtualFilesystem) -> None:
    target_linux._name = "not_local"
    with patch("dissect.target.plugins.os.unix.esxi._os.HAS_ENVELOPE", False):
        assert _create_local_fs(target_linux, fs_unix.path(""), fs_unix.path("")) is None


def test__decrypt_crypto_local(fs_unix: VirtualFilesystem) -> None:
    with patch("dissect.target.plugins.os.unix.esxi._os.subprocess.run") as mocked_run:
        mocked_run.return_value.stdout = b"data"

        assert _decrypt_crypto_util(fs_unix.path("data")).read() == b"data"


def test_esxi_os_detection(target_bare: Target, fs_esxi: VirtualFilesystem) -> None:
    target_bare.filesystems.add(fs_esxi)
    target_bare.apply()

    assert ESXiPlugin.detect(target_bare)
    assert isinstance(target_bare._os, ESXiPlugin)
    assert target_bare.os == OperatingSystem.ESXI
    assert target_bare.hostname == "localhost"
    assert target_bare.version == "6.7.0"
    assert target_bare.ips == ["192.168.56.101"]


def test_esxi_os_creation_version_7(target_bare: Target) -> None:
    """Test handling of ``ESXiPlugin.create`` for ESXi 7 with separate partitions.
    Indirectly tests the ESXi configstore plugin."""

    fs1 = VirtualFilesystem()
    fs1.map_file_fh("boot.cfg", BytesIO(b"build=7.13.37-1.2.3.4\nmodules=example.v00 --- example.tgz\n"))
    fs1.map_file_fh("example.v00", BytesIO(b""))
    target_bare.filesystems.add(fs1)

    fs2 = VirtualFilesystem()
    fs2.map_file_fh("/etc/vmware/esx.conf", BytesIO(b'/resourceGroups/version = "7.13.37"\n'))
    fs2.map_file("/var/lib/vmware/configstore/backup/current-store-1", absolute_path("_data/plugins/os/unix/esxi/current-store-1"))
    target_bare.filesystems.add(fs2)

    target_bare.apply()

    assert ESXiPlugin.detect(target_bare)
    assert ESXiPlugin.create(target_bare, fs1)
