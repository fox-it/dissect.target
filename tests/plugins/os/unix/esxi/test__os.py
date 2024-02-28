from unittest.mock import patch

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.esxi._os import (
    _create_local_fs,
    _decrypt_crypto_util,
)


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
