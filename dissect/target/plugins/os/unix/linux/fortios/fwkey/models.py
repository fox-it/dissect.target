from __future__ import annotations

from dataclasses import dataclass


@dataclass(unsafe_hash=True)
class RawKeyCandidate:
    raw_key: bytes
    rsa_blob: bytes
    key_offset: int | None = None
    blob_offset: int | None = None


# FortiOS 7.6.5+, v8.0.0+ uses custom RC4
@dataclass(unsafe_hash=True)
class RC4Key:
    key: bytes
    i_bits: int = 0
    reset_j: bool = False

    def __init__(self, key: bytes | str, i_bits: int = 0, reset_j: bool = True):
        self.key = bytes.fromhex(key) if isinstance(key, str) else key
        self.i_bits = i_bits
        self.reset_j = reset_j

    def __repr__(self) -> str:
        return f"RC4Key(key={self.key.hex()!r}, i_bits={self.i_bits!r}, reset_j={self.reset_j!r})"


# FortiOS 7.0.16+, 7.2.9+, 7.4.4+, 7.6.0-4 and higher uses AES-CTR with a custom CTR increment
@dataclass(unsafe_hash=True)
class AesKey:
    key: bytes
    iv: bytes

    def __init__(self, key: bytes | str, iv: bytes | str):
        self.key = bytes.fromhex(key) if isinstance(key, str) else key
        self.iv = bytes.fromhex(iv) if isinstance(iv, str) else iv

    def __repr__(self) -> str:
        return f"AesKey(key={self.key.hex()!r}, iv={self.iv.hex()!r})"


# FortiOS 7.0.13 and 7.0.14 uses a static key and IV
@dataclass(unsafe_hash=True)
class ChaCha20Key:
    key: bytes
    iv: bytes

    def __init__(self, key: bytes | str, iv: bytes | str):
        self.key = bytes.fromhex(key) if isinstance(key, str) else key
        self.iv = bytes.fromhex(iv) if isinstance(iv, str) else iv

    def __repr__(self) -> str:
        return f"ChaCha20Key(key={self.key.hex()!r}, iv={self.iv.hex()!r})"


# FortiOS 7.4.x uses a KDF to derive the key and IV
@dataclass(unsafe_hash=True)
class ChaCha20Seed:
    key: bytes
    offset_key: int = 4
    offset_iv: int = 5

    def __init__(self, key: bytes | str, offset_key: int = 4, offset_iv: int = 5):
        self.key = bytes.fromhex(key) if isinstance(key, str) else key
        self.offset_key = offset_key
        self.offset_iv = offset_iv

    def __repr__(self) -> str:
        return f"ChaCha20Seed(key={self.key.hex()!r}, offset_key={self.offset_key}, offset_iv={self.offset_iv})"


FirmwareKey = RC4Key | AesKey | ChaCha20Key | ChaCha20Seed
