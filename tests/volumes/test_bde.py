from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO
from unittest.mock import patch

import pytest

from dissect.target import volume
from dissect.target.helpers import keychain
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

try:
    from dissect.target.volumes.bde import BitlockerVolumeSystem

    HAS_DISSECT_FVE = True
except ModuleNotFoundError:
    HAS_DISSECT_FVE = False


@pytest.fixture
def encrypted_volume() -> Iterator[BinaryIO]:
    data_file = "_data/volumes/bde/enc-volume.bin"
    with absolute_path(data_file).open("rb") as fh:
        yield fh


@pytest.mark.skipif(not HAS_DISSECT_FVE, reason="requires dissect.fve")
def test_bde_volume_failure(target_win: Target, encrypted_volume: BinaryIO) -> None:
    """Test if not providing a key to decrypt a BDE volume results in no mounted volume."""

    enc_vol = volume.Volume(encrypted_volume, 1, 0, None, None, None, disk=encrypted_volume)
    target_win.volumes.add(enc_vol)
    target_win.volumes.apply()

    assert len(target_win.volumes) == 1
    assert enc_vol in target_win.volumes


@pytest.mark.skipif(not HAS_DISSECT_FVE, reason="requires dissect.fve")
def test_bde_volume_with_recovery_key(target_win: Target, encrypted_volume: BinaryIO) -> None:
    """Test if we can decrypt a BDE volume using a recovery key."""

    recovery_key = "272316-265804-640728-713570-509047-503305-045837-324731"

    with patch.object(keychain, "KEYCHAIN", []):
        keychain.register_key(
            keychain.KeyType.RECOVERY_KEY,
            recovery_key,
            identifier=None,
            provider=BitlockerVolumeSystem.__type__,
        )

        enc_vol = volume.Volume(encrypted_volume, 1, 0, None, None, None, disk=encrypted_volume)
        target_win.volumes.add(enc_vol)
        target_win.volumes.apply()

        assert len(target_win.volumes) == 2
        assert enc_vol in target_win.volumes

        dec_vol = next(v for v in target_win.volumes if v != enc_vol)

        # virtual fs + ntfs fs
        assert len(target_win.filesystems) == 2
        target_win.fs.mount("e:/", dec_vol.fs)

        assert target_win.fs.path("e:/test-folder/test-file-2.txt").exists()


@pytest.mark.skipif(not HAS_DISSECT_FVE, reason="requires dissect.fve")
def test_bde_volume_with_passphrase(target_win: Target, encrypted_volume: BinaryIO) -> None:
    """Test if we can decrypt a BDE volume using a passphrase."""

    identifier = "B6AD258A-2725-4A42-93C6-844478BF7A90"
    passphrase = "Password1234"

    with patch.object(keychain, "KEYCHAIN", []):
        keychain.register_key(
            keychain.KeyType.PASSPHRASE,
            passphrase,
            identifier=identifier,
            provider=BitlockerVolumeSystem.__type__,
        )

        enc_vol = volume.Volume(encrypted_volume, 1, 0, None, None, None, disk=encrypted_volume)
        target_win.volumes.add(enc_vol)
        target_win.volumes.apply()

        assert len(target_win.volumes) == 2
        assert enc_vol in target_win.volumes

        dec_vol = next(v for v in target_win.volumes if v != enc_vol)

        # virtual fs + ntfs fs
        assert len(target_win.filesystems) == 2
        target_win.fs.mount("e:/", dec_vol.fs)

        assert target_win.fs.path("e:/test-folder/test-file-2.txt").exists()


@pytest.mark.skipif(not HAS_DISSECT_FVE, reason="requires dissect.fve")
def test_bde_volume_with_wildcard_key(target_win: Target, encrypted_volume: BinaryIO) -> None:
    """Test if we can decrypt a BDE volume using a wildcard keychain key."""

    with patch.object(keychain, "KEYCHAIN", []):
        keychain.register_wildcard_value("Password1234")

        enc_vol = volume.Volume(encrypted_volume, 1, 0, None, None, None, disk=encrypted_volume)
        target_win.volumes.add(enc_vol)
        target_win.volumes.apply()

        assert len(target_win.volumes) == 2
        assert enc_vol in target_win.volumes

        dec_vol = next(v for v in target_win.volumes if v != enc_vol)

        # virtual fs + ntfs fs
        assert len(target_win.filesystems) == 2
        target_win.fs.mount("e:/", dec_vol.fs)

        assert target_win.fs.path("e:/test-folder/test-file-2.txt").exists()


@pytest.mark.skipif(not HAS_DISSECT_FVE, reason="requires dissect.fve")
def test_bde_volume_with_raw_key(target_win: Target, encrypted_volume: BinaryIO) -> None:
    """Test if we can decrypt a BDE volume using a raw FVEK key."""

    with patch.object(keychain, "KEYCHAIN", []):
        keychain.register_wildcard_value("ab60a58f1a0b60be91ffa2b40ec338a072a011302a8ff58fc45eee742711dc7f")

        enc_vol = volume.Volume(encrypted_volume, 1, 0, None, None, None, disk=encrypted_volume)
        target_win.volumes.add(enc_vol)
        target_win.volumes.apply()

        assert len(target_win.volumes) == 2
        assert enc_vol in target_win.volumes

        dec_vol = next(v for v in target_win.volumes if v != enc_vol)

        # virtual fs + ntfs fs
        assert len(target_win.filesystems) == 2
        target_win.fs.mount("e:/", dec_vol.fs)

        assert target_win.fs.path("e:/test-folder/test-file-2.txt").exists()
