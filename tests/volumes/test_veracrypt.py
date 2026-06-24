from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO
from unittest.mock import patch

import pytest

from dissect.target import volume
from dissect.target.helpers import hashutil, keychain
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

try:
    from dissect.target.volumes.veracrypt import VeraCryptVolumeSystem

    HAS_DISSECT_FVE = True
except ModuleNotFoundError:
    HAS_DISSECT_FVE = False


@pytest.fixture
def encrypted_volume() -> Iterator[BinaryIO]:
    with absolute_path("_data/volumes/veracrypt/enc-volume.bin").open("rb") as fh:
        yield fh


@pytest.mark.skipif(not HAS_DISSECT_FVE, reason="requires dissect.fve")
def test_veracrypt_volume_with_wildcard_key(target_win: Target, encrypted_volume: BinaryIO) -> None:
    """Test if we can decrypt a simple AES-256 HMAC-SHA-512 VeraCrypt volume using a wildcard keychain key."""
    with patch.object(keychain, "KEYCHAIN", []):
        keychain.register_wildcard_value("password")

        assert volume.is_encrypted(encrypted_volume)

        vol = next(volume.open_encrypted(encrypted_volume))
        assert isinstance(vol.vs, VeraCryptVolumeSystem)

        target_win.volumes.add(vol)
        target_win.volumes.apply()
        assert vol in target_win.volumes
        assert len(target_win.filesystems) == 2
        target_win.fs.mount("e:/", vol.fs)

        assert target_win.fs.path("e:/hello.txt").exists()
        assert target_win.fs.path("e:/hello.txt").read_text() == "Hello world!\n"
        with target_win.fs.path("e:/poster-summerschool-vierkant.jpg").open("rb") as fh:
            assert hashutil.sha1(fh) == "c81deb8714fb197bd7840f2ee64473e4c16bb16f"
