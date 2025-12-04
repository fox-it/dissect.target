from __future__ import annotations

import gzip
from typing import TYPE_CHECKING

from dissect.target.filesystems.apfs import ApfsFilesystem
from dissect.target.helpers import keychain
from tests._utils import absolute_path

if TYPE_CHECKING:
    import pytest


def test_apfs_encrypted(caplog: pytest.LogCaptureFixture) -> None:
    """Test that encrypted APFS filesystems are correctly detected."""
    with gzip.open(absolute_path("_data/filesystems/apfs/encrypted.bin.gz"), "rb") as fh:
        assert ApfsFilesystem.detect(fh)

        fs = ApfsFilesystem(fh)
        assert caplog.messages == [
            "Failed to open APFS volume 'Encrypted' (0a51df00-e6ff-6949-9607-efa24d864392): No valid decryption key found"  # noqa: E501
        ]

        # Test with wildcard key
        keychain.register_wildcard_value("password")
        fs = ApfsFilesystem(fh)
        assert len(list(fs.iter_subfs())) == 1
        assert len(next(fs.iter_subfs()).get("/").listdir()) == 11

        # Test with UUID
        keychain.KEYCHAIN.clear()
        keychain.register_key(
            keychain.KeyType.PASSPHRASE,
            "password",
            "0a51df00-e6ff-6949-9607-efa24d864392",
            provider="apfs",
        )
        fs = ApfsFilesystem(fh)
        assert len(list(fs.iter_subfs())) == 1
        assert len(next(fs.iter_subfs()).get("/").listdir()) == 11


def test_apfs_direntry() -> None:
    """Test APFS directory entries and symlink behavior."""
    with gzip.open(absolute_path("_data/filesystems/apfs/encrypted.bin.gz"), "rb") as fh:
        assert ApfsFilesystem.detect(fh)

        keychain.register_wildcard_value("password")
        fs = ApfsFilesystem(fh)
        volume = next(fs.iter_subfs())
        root = volume.get("/")

        dirents = {entry.name: entry for entry in root.scandir()}
        assert len(dirents) == 11

        assert dirents["dir"].is_dir(follow_symlinks=False)
        assert dirents["dir"].is_dir(follow_symlinks=True)
        assert dirents["symlink-dir"].is_symlink()
        assert not dirents["symlink-dir"].is_dir(follow_symlinks=False)
        assert dirents["symlink-dir"].is_dir(follow_symlinks=True)
