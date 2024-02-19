from io import BytesIO
from unittest.mock import patch

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.esxi._os import _create_tar_fs, _decrypt_crypto_util
from dissect.target.target import Target


def test__create_tar_fs_no_envelope(target_linux: Target, fs_unix: VirtualFilesystem):
    with (
        patch("dissect.target.plugins.os.unix.esxi._os.HAS_ENVELOPE", False),
        patch("dissect.target.plugins.os.unix.esxi._os.tar") as mocked_tar,
        patch("dissect.target.plugins.os.unix.esxi._os._decrypt_crypto_util") as decrypt_func,
    ):
        _create_tar_fs(target_linux, fs_unix.path("local.tgz.ve"), fs_unix.path("encryption.info"))

        decrypt_func.assert_called()
        mocked_tar.TarFilesystem.assert_called()


def test__create_tar_fs_envelope(target_linux: Target, fs_unix: VirtualFilesystem):
    with (
        patch("dissect.target.plugins.os.unix.esxi._os.HAS_ENVELOPE", True),
        patch("dissect.target.plugins.os.unix.esxi._os.tar") as mocked_tar,
        patch("dissect.target.plugins.os.unix.esxi._os._decrypt_envelope") as decrypt_func,
    ):
        _create_tar_fs(target_linux, fs_unix.path("local.tgz.ve"), fs_unix.path("encryption.info"))

        decrypt_func.assert_called()
        mocked_tar.TarFilesystem.assert_called()


def test__create_tar_fs_failed_envelope(target_linux: Target, fs_unix: VirtualFilesystem):
    with (
        patch("dissect.target.plugins.os.unix.esxi._os.HAS_ENVELOPE", True),
        patch("dissect.target.plugins.os.unix.esxi._os.tar") as mocked_tar,
        patch("dissect.target.plugins.os.unix.esxi._os._decrypt_envelope", side_effect=[NotImplementedError]),
        patch("dissect.target.plugins.os.unix.esxi._os._decrypt_crypto_util") as decrypt_func,
    ):
        _create_tar_fs(target_linux, fs_unix.path("local.tgz.ve"), fs_unix.path("encryption.info"))

        decrypt_func.assert_called()
        mocked_tar.TarFilesystem.assert_called()


def test__decrypt_crypto_not_local(target_linux: Target, fs_unix: VirtualFilesystem):
    target_linux._name = "not_local"

    assert _decrypt_crypto_util(target_linux, fs_unix.path("")) is None


def test__decrypt_crypto_local(target_linux: Target, fs_unix: VirtualFilesystem):
    target_linux._name = "local"

    with patch("dissect.target.plugins.os.unix.esxi._os.Popen") as mocked_popen:
        mocked_popen.return_value.__enter__.return_value.stdout = BytesIO(b"data")

        assert _decrypt_crypto_util(target_linux, fs_unix.path("data")).read() == b"data"
