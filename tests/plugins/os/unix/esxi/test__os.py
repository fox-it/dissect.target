from __future__ import annotations

import typing
from io import BytesIO
from unittest.mock import patch

import pytest
from flow.record.fieldtypes import datetime as dt

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import open as loader_open
from dissect.target.plugin import OperatingSystem
from dissect.target.plugins.os.unix.esxi._os import ESXiPlugin, _create_local_fs, _decrypt_crypto_util
from dissect.target.target import Target
from tests._utils import absolute_path

if typing.TYPE_CHECKING:
    import datetime


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


@pytest.mark.parametrize(
    ("data_path", "hostname", "ips", "version", "users"),
    [
        (
            "_data/loaders/vmsupport/esx-localhost6-2026-01-12--13.56-2107676.tar.gz",
            "localhost",
            ["192.168.122.133"],
            "6.7.0-14320388",
            # vm support does not contains the /etc/passwd file, thus no user are returned
            [],
        ),
        (
            "_data/loaders/vmsupport/esx-localhost7-2026-01-20--09.27-139218.tgz",
            "localhost",
            ["192.168.122.186"],
            "7.0.3-0.50.20036589",
            [
                ("dcui", "DCUI User", dt("2026-01-20 09:24:23+00:00"), dt("2026-01-20 09:24:23+00:00"), True),
                ("dissect", "Test dissect", dt("2026-01-20 09:24:23+00:00"), dt("2026-01-20 09:24:23+00:00"), True),
                ("root", "Administrator", dt("2026-01-20 09:24:23+00:00"), dt("2026-01-20 09:24:23+00:00"), True),
                (
                    "vpxuser",
                    "VMware VirtualCenter administration account",
                    dt("2026-01-20 09:24:23+00:00"),
                    dt("2026-01-20 09:24:23+00:00"),
                    True,
                ),
            ],
        ),
        (
            "_data/loaders/vmsupport/esx-localhost8-2026-01-09--16.04-135806.tgz",
            "localhost",
            ["192.168.122.207"],
            "8.0.3-0.70.24677879",
            [("root", "Administrator", dt("2026-01-09 15:59:34+00:00"), dt("2026-01-09 15:59:34+00:00"), True)],
        ),
        (
            "_data/loaders/vmsupport/esx-localhost9-2026-01-09--16.26-149929.tgz",
            "localhost",
            ["192.168.122.43"],
            "9.0.0-0.24678710",
            [("root", "Administrator", dt("2026-01-09 16:20:11+00:00"), dt("2026-01-09 16:20:11+00:00"), True)],
        ),
    ],
)
def test_esxi_os_detection_from_vmsupport(
    data_path: str,
    hostname: str,
    ips: list[str],
    version: str,
    users: list[tuple[str, str | None, datetime.datetime | None, datetime.datetime | None, bool | None]],
) -> None:
    """Test if os function works on a vmsupport collection."""
    """"
    TODO for test:
    * Create user
    * Change log folder
    * Change hostname
    """
    path = absolute_path(data_path)
    loader = loader_open(path)
    target = Target()
    loader.map(target)
    target.apply()
    assert isinstance(target._os, ESXiPlugin)
    assert target.os == OperatingSystem.ESXI
    assert target.hostname == hostname
    assert target.version == version
    assert target.ips == ips
    assert target.domain == ""
    assert (
        sorted(
            [
                (
                    u.name,
                    getattr(u, "description", None),
                    getattr(u, "modified_time", None),
                    getattr(u, "creation_time", None),
                    getattr(u, "shell_access", None),
                )
                for u in list(target.users())
            ],
            key=lambda x: x[0],
        )
        == users
    )


def test_esxi_os_creation_version_7(target_bare: Target) -> None:
    """Test handling of ``ESXiPlugin.create`` for ESXi 7 with separate partitions.

    Indirectly tests the ESXi configstore plugin.
    """

    fs1 = VirtualFilesystem()
    fs1.map_file_fh("boot.cfg", BytesIO(b"build=7.13.37-1.2.3.4\nmodules=example.v00 --- example.tgz\n"))
    fs1.map_file_fh("example.v00", BytesIO(b""))
    target_bare.filesystems.add(fs1)

    fs2 = VirtualFilesystem()
    fs2.map_file_fh("/etc/vmware/esx.conf", BytesIO(b'/resourceGroups/version = "7.13.37"\n'))
    fs2.map_file(
        "/var/lib/vmware/configstore/backup/current-store-1",
        absolute_path("_data/plugins/os/unix/esxi/current-store-1"),
    )
    target_bare.filesystems.add(fs2)

    target_bare.apply()

    assert ESXiPlugin.detect(target_bare)
    assert ESXiPlugin.create(target_bare, fs1)
