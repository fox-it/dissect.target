from __future__ import annotations

from hashlib import sha256


def kdf_7_4_x(key_data: str | bytes, offset_key: int = 4, offset_iv: int = 5) -> tuple[bytes, bytes]:
    """Derive 32 byte key and 16 byte IV from 32 byte seed.

    As the IV needs to be 16 bytes, we return the first 16 bytes of the sha256 hash.
    """
    if isinstance(key_data, str):
        key_data = bytes.fromhex(key_data)

    assert len(key_data) == 32, f"key_data must be 32 bytes, got {len(key_data)} bytes"

    key = sha256(key_data[offset_key:32] + key_data[:offset_key]).digest()
    iv = sha256(key_data[offset_iv:32] + key_data[:offset_iv]).digest()[:16]
    return key, iv
