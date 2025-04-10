from __future__ import annotations

from io import BytesIO

import pytest

from dissect.target.plugins.os.unix.linux.fortios._keys import (
    KERNEL_KEY_MAP,
    AesKey,
    ChaCha20Key,
    ChaCha20Seed,
)
from dissect.target.plugins.os.unix.linux.fortios._os import (
    aes_decrypt,
    decrypt_rootfs,
    key_iv_for_kernel_hash,
)


def test_kernel_key_map() -> None:
    # Ensure that the kernel key map is valid
    for kernel_hash, key in KERNEL_KEY_MAP.items():
        # test if the kernel hash is a valid hex string
        assert bytes.fromhex(kernel_hash)
        # test if the kernel hash is a valid length (sha256)
        assert len(bytes.fromhex(kernel_hash)) == 32

        assert isinstance(key, (AesKey, ChaCha20Key, ChaCha20Seed))

        assert isinstance(key.key, bytes)
        assert len(key.key) == 32

        if hasattr(key, "iv"):
            assert isinstance(key.iv, bytes)
            assert len(key.iv) == 16


def test_key_iv_for_kernel_hash() -> None:
    # test FFW_1801F-v7.4.2.F-build2571-FORTINET (KDF)
    key = key_iv_for_kernel_hash("d719f7fd533d05efb872907cf3711d0d895750d288b856ce70fefecbd7ace482")
    assert key.key == bytes.fromhex("39ef9ceb4262b49252164a4558b14a9b006d91a5247f5c797af281fade2198a8")
    assert key.iv == bytes.fromhex("f30a9e100417e2c390b763d2be2f2d03")

    # test FFW_3980E-v7.0.14.M-build0601-FORTINET (static key + IV)
    key = key_iv_for_kernel_hash("a494ec1713ab75a5ab58a847f096951e2de7ba899bef1a9a88a9c94d8efc4749")
    assert key.key == bytes.fromhex("bb48ece8482e277f307479b8923796aed3b536e83f5fadc0d758b36192626762")
    assert key.iv == bytes.fromhex("5394687ae6c679a74c7901267dfb9bb3")

    # test unknown hash
    with pytest.raises(ValueError, match="No known decryption keys for kernel hash: .*"):
        key_iv_for_kernel_hash("12345")


def test_decrypt_rootfs() -> None:
    # test decrypt of rootfs.gz header (FWF_81F_2R_POE-v7.4.3.F-build2573-FORTINET)
    encrypted_rootfs_header = bytes.fromhex("3ccb 7d85 b9b0 4c8e 8c92 36d4 1d9c c48c")
    key = bytes.fromhex("b9c77cfca5c3f4fe543b5b861b5eeab61b0bfd23fa93f52f5cd428bb5567ec37")
    iv = bytes.fromhex("25c9578ca8d04f8c55009ae41657d7dd")
    fh = decrypt_rootfs(BytesIO(encrypted_rootfs_header), ChaCha20Key(key, iv))
    assert fh.read(16) == b"\x1f\x8b\x08\x00J\xd6\xbbe\x00\x03\xa4\xb6S\x900\x00"

    # test bad decrypt
    bad_key = ChaCha20Key(key[::-1], iv[::-1])
    with pytest.raises(ValueError, match="Failed to decrypt: No gzip magic header found."):
        decrypt_rootfs(BytesIO(encrypted_rootfs_header), bad_key)


def test_aes_decrypt() -> None:
    # encrypted FGT_VM64_AZURE-v7.6.0.F-build3401-FORTINET.out/rootfs.gz
    encrypted_rootfs_header = bytes.fromhex(
        """
    3cd7 cc80 3328 3d18 4601 d1de 6440 e41b
    bf60 0a4a eb2b e38f 4068 8123 37d9
    """
    )
    decrypted_rootfs_header = bytes.fromhex(
        """
    1f8b 0800 f33f a166 0003 a4b6 638c 2e50
    b3a8 f9b6 6ddb b66d dbd8 6ddb ddbb
        """
    )
    key = KERNEL_KEY_MAP.get("5a4c18b9118124049955caa29824188d92fc51741f9576f90ea7a9df082b7657")
    assert isinstance(key, AesKey)
    data = aes_decrypt(BytesIO(encrypted_rootfs_header), key)
    assert data == decrypted_rootfs_header
