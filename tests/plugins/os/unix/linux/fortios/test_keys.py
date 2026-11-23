from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers import keychain
from dissect.target.plugins.os.unix.linux.fortios._keys import KERNEL_KEY_MAP
from dissect.target.plugins.os.unix.linux.fortios._os import (
    decrypt_rootfs,
    key_iv_from_keychain,
)
from dissect.target.plugins.os.unix.linux.fortios.fwkey.ciphers import aes_decrypt, rc4_crypt
from dissect.target.plugins.os.unix.linux.fortios.fwkey.kdf import kdf_7_4_x
from dissect.target.plugins.os.unix.linux.fortios.fwkey.models import (
    AesKey,
    ChaCha20Key,
    ChaCha20Seed,
    RC4Key,
)

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


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
    key = KERNEL_KEY_MAP["d719f7fd533d05efb872907cf3711d0d895750d288b856ce70fefecbd7ace482"]
    assert isinstance(key, ChaCha20Seed)
    derived_key, derived_iv = kdf_7_4_x(key.key)
    assert derived_key == bytes.fromhex("39ef9ceb4262b49252164a4558b14a9b006d91a5247f5c797af281fade2198a8")
    assert derived_iv == bytes.fromhex("f30a9e100417e2c390b763d2be2f2d03")

    # test FFW_3980E-v7.0.14.M-build0601-FORTINET (static key + IV)
    key = KERNEL_KEY_MAP["a494ec1713ab75a5ab58a847f096951e2de7ba899bef1a9a88a9c94d8efc4749"]
    assert isinstance(key, ChaCha20Key)
    assert key.key == bytes.fromhex("bb48ece8482e277f307479b8923796aed3b536e83f5fadc0d758b36192626762")
    assert key.iv == bytes.fromhex("5394687ae6c679a74c7901267dfb9bb3")

    # test unknown hash
    with pytest.raises(KeyError):
        KERNEL_KEY_MAP["12345"]


def test_decrypt_rootfs() -> None:
    # test decrypt of rootfs.gz header (FWF_81F_2R_POE-v7.4.3.F-build2573-FORTINET)
    encrypted_rootfs_header = bytes.fromhex("3ccb 7d85 b9b0 4c8e 8c92 36d4 1d9c c48c")
    key = bytes.fromhex("b9c77cfca5c3f4fe543b5b861b5eeab61b0bfd23fa93f52f5cd428bb5567ec37")
    iv = bytes.fromhex("25c9578ca8d04f8c55009ae41657d7dd")
    data = decrypt_rootfs(encrypted_rootfs_header, ChaCha20Key(key, iv))
    assert data[:16] == b"\x1f\x8b\x08\x00J\xd6\xbbe\x00\x03\xa4\xb6S\x900\x00"

    # test bad decrypt
    bad_key = ChaCha20Key(key[::-1], iv[::-1])
    with pytest.raises(ValueError, match=re.escape("Failed to decrypt: No gzip magic header found.")):
        decrypt_rootfs(encrypted_rootfs_header, bad_key)


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
    data = aes_decrypt(encrypted_rootfs_header, key.key, key.iv)
    assert data == decrypted_rootfs_header


def test_rc4_decrypt() -> None:
    # encrypted fortinet-fgtondemand-arm64-800-20260423 (FGT_ARM64_GCP)
    encrypted_rootfs_header = bytes.fromhex(
        """
        f754 8e2d 8ef2 0f2c fd3e 93f8 39bd b253
        dc8f 7be6 8a23 0102 e06a 2c35 e96c a70a
        """
    )
    decrypted_rootfs_header = bytes.fromhex(
        """
        1f8b 0800 e467 e669 0003 9cb7 53ac 3000
        afa6 bb6c dbb6 6ddb b66d dbb6 6ddb f896
        """
    )
    key = RC4Key(key="8b82eca163d676c922ce4f21820aa1934d8b065c810f77e44a5aa59517189f45", i_bits=3, reset_j=True)
    assert isinstance(key, RC4Key)
    data = rc4_crypt(encrypted_rootfs_header, key.key, i_bits=key.i_bits, reset_j=key.reset_j)
    assert data == decrypted_rootfs_header


def test_decrypt_rootfs_from_keychain_file(target_unix: Target, tmp_path: Path) -> None:
    # encrypted FGT_1000D-v7.6.4.F-build3596-FORTINET.out/rootfs.gz
    kernel_hash = "8e7fb3af9fe68d69af224857164347cee271264308c8ba86e9ad036e405ac6c8"
    encrypted_rootfs_header = bytes.fromhex(
        """
    d739 ba66 6d65 ca64 4295 b7e4 3c48 7165
    49ab e60c fc39 ef48 30b0 06cd f32c 37f2
    """
    )
    decrypted_rootfs_header = bytes.fromhex(
        """
    1f8b 0800 4d07 a668 0003 a4d3 5390 2ed0
    d226 e8c2 aeaf 6cdb b66d dbb6 6d57 edb2
    """
    )

    keys = key_iv_from_keychain(target_unix, kernel_hash=kernel_hash)
    assert not keys, "Keys found in keychain when none were expected"

    keychain_file = tmp_path / "fortios_keychain.csv"
    keychain_file.write_text(
        "fortios-aeskey,recovery_key,"
        "8e7fb3af9fe68d69af224857164347cee271264308c8ba86e9ad036e405ac6c8,"
        "5adbbe614bcde31c3e05ba2e261c1a2410f0900ed340689835520a0612fc612b:e4973d6eff0412b4dbf4fe43c4d3136d"
    )
    keychain.register_keychain_file(keychain_file)

    keys = key_iv_from_keychain(target_unix, kernel_hash=kernel_hash)
    assert keys, "No keys found in keychain for testing"

    for key in keys:
        assert isinstance(key, AesKey)
        assert key.key == bytes.fromhex("5adbbe614bcde31c3e05ba2e261c1a2410f0900ed340689835520a0612fc612b")
        assert key.iv == bytes.fromhex("e4973d6eff0412b4dbf4fe43c4d3136d")

        data = decrypt_rootfs(encrypted_rootfs_header, key)
        assert data == decrypted_rootfs_header


def test_decrypt_rootfs_from_keychain_value(target_unix: Target) -> None:
    # encrypted FGT_1000D-v7.6.4.F-build3596-FORTINET.out/rootfs.gz
    kernel_hash = "8e7fb3af9fe68d69af224857164347cee271264308c8ba86e9ad036e405ac6c8"
    encrypted_rootfs_header = bytes.fromhex(
        """
    d739 ba66 6d65 ca64 4295 b7e4 3c48 7165
    49ab e60c fc39 ef48 30b0 06cd f32c 37f2
    """
    )
    decrypted_rootfs_header = bytes.fromhex(
        """
    1f8b 0800 4d07 a668 0003 a4d3 5390 2ed0
    d226 e8c2 aeaf 6cdb b66d dbb6 6d57 edb2
    """
    )

    keys = key_iv_from_keychain(target_unix, kernel_hash=kernel_hash)
    assert not keys, "Keys found in keychain when none were expected"

    keychain.register_wildcard_value(
        "5adbbe614bcde31c3e05ba2e261c1a2410f0900ed340689835520a0612fc612b:e4973d6eff0412b4dbf4fe43c4d3136d"
    )

    keys = key_iv_from_keychain(target_unix, kernel_hash=kernel_hash)
    assert keys, "No keys found in keychain for testing"

    for key in keys:
        # the keychain code expands the given key to both AesKey and ChaCha20Key
        assert isinstance(key, (AesKey, ChaCha20Key))
        assert key.key == bytes.fromhex("5adbbe614bcde31c3e05ba2e261c1a2410f0900ed340689835520a0612fc612b")
        assert key.iv == bytes.fromhex("e4973d6eff0412b4dbf4fe43c4d3136d")

        # The ChaCha20Key is not the correct one, so it should fail to decrypt
        if isinstance(key, ChaCha20Key):
            with pytest.raises(ValueError, match="Failed to decrypt: No gzip magic header found"):
                data = decrypt_rootfs(encrypted_rootfs_header, key)

        # the AesKey is the correct one
        if isinstance(key, AesKey):
            data = decrypt_rootfs(encrypted_rootfs_header, key)
            assert data == decrypted_rootfs_header
