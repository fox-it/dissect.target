from __future__ import annotations

import struct

from Crypto.Cipher import AES, ChaCha20
from Crypto.PublicKey import RSA
from Crypto.Util import Counter


def xor(data: bytes, key: bytes) -> bytes:
    """XOR data with key (simd version)."""
    if sum(key) == 0:
        return data

    size = len(data)
    if len(key) < size:
        key = key * ((size // len(key)) + 1)
    key = key[:size]

    return int.to_bytes(int.from_bytes(data, "little") ^ int.from_bytes(key, "little"), size, "little")


def calculate_counter_increment(iv: bytes) -> int:
    """Calculate the custom FortiGate CTR increment from IV.

    Args:
        iv: 16 bytes IV.

    Returns:
        Custom CTR increment.
    """
    increment = 0
    for i in range(16):
        increment ^= (iv[i] & 15) ^ ((iv[i] >> 4) & 0xFF)
    return max(increment, 1)


def aes_decrypt(buffer: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt buffer using a custom AES CTR increment with given AesKey.

    Args:
        buffer: data to decrypt.
        key: AES key.
        iv: AES iv.

    Returns:
        Decrypted bytes.
    """
    data = bytearray(buffer)

    # Calculate custom CTR increment from IV
    increment = calculate_counter_increment(iv)
    advance_block = (b"\x69" * 16) * (increment - 1)

    # AES counter is little-endian and has a prefix
    prefix, counter = struct.unpack("<8sQ", iv)
    ctr = Counter.new(
        64,
        prefix=prefix,
        initial_value=counter,
        little_endian=True,
        allow_wraparound=True,
    )
    cipher = AES.new(key, mode=AES.MODE_CTR, counter=ctr)

    nblocks, nleft = divmod(len(data), 16)
    for i in range(nblocks):
        offset = i * 16
        data[offset : offset + 16] = cipher.decrypt(data[offset : offset + 16])
        cipher.decrypt(advance_block)  # custom advance the counter

    if nleft:
        data[nblocks * 16 :] = cipher.decrypt(data[nblocks * 16 :])

    return bytes(data)


def chacha20_crypt(buffer: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt/Decrypt buffer using ChaCha20 with given key and iv.

    Args:
        buffer: data to encrypt/decrypt.
        key: ChaCha20 key.
        iv: ChaCha20 iv.

    Returns:
        Encrypted/decrypted bytes.
    """
    # First 8 bytes = counter, last 8 bytes = nonce
    # PyCryptodome interally divides this seek by 64 to get a (position, offset) tuple
    # We're interested in updating the position in the ChaCha20 internal state, so to make
    # PyCryptodome "OpenSSL-compatible" we have to multiply the counter by 64
    cipher = ChaCha20.new(key=key, nonce=iv[4:])
    try:
        cipher.seek(int.from_bytes(iv[:4], "little") * 64)
    except ValueError:
        return b""
    return cipher.decrypt(buffer)


def rc4_crypt(data: bytes, key: bytes, *, i_bits: int = 5, reset_j: bool = True, mix_const: int = 0xAA) -> bytes:
    """Modified RC4 crypt from FortiGate, with cross-mixed indices and optional reset of j.

    Args:
        data: data to encrypt/decrypt.
        key: RC4 key.
        i_bits: number of bits for cross-mixed indices.
        reset_j: whether to reset j.
        mix_const: mix constant.

    Returns:
        Encrypted/decrypted bytes.
    """
    assert 1 <= i_bits <= 7
    mask, shift = (1 << i_bits) - 1, 8 - i_bits

    if len(key) < 32:
        raise ValueError("key must be at least 32 bytes (indexed as key[i & 0x1F])")

    # KSA (standard; key[i % len(key)], i.e. key[i & 0x1F] for a 32-byte key)
    S = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xFF
        S[i], S[j] = S[j], S[i]

    # PRGA (modified keystream)
    i = 0
    if reset_j:
        j = 0
    out = bytearray(data)
    for pos in range(len(data)):
        i = (i + 1) & 0xFF
        si = S[i]
        j = (j + si) & 0xFF
        sj = S[j]
        S[i], S[j] = sj, si  # swap
        idx_a = ((i & mask) << shift) | (j >> i_bits)  # cross-mixed index
        idx_b = ((j & mask) << shift) | (i >> i_bits)
        P = S[((S[idx_a] + S[idx_b]) & 0xFF) ^ mix_const]
        Q = S[(si + sj) & 0xFF]
        R = S[(sj + j) & 0xFF]
        out[pos] ^= ((P + Q) ^ R) & 0xFF
    return bytes(out)


def rsa_public_decrypt(public_key: bytes, ciphertext: bytes) -> bytes:
    """Recover a message from an RSA public-key operation (PKCS#1 v1.5, block type 01).

    Args:
        public_key: RSA public key (DER/PEM, as accepted by RSA.import_key).
        ciphertext: signature/blob (produced with the private key) to recover.

    Returns:
        The recovered message (padding stripped).

    Raises:
        ValueError: If the public key is invalid or the recovered block does not have valid PKCS#1 v1.5 type-01 padding.
    """
    pub = RSA.import_key(public_key)
    c = int.from_bytes(ciphertext, "big")
    m = pow(c, pub.e, pub.n)
    block = m.to_bytes(pub.size_in_bytes(), "big")

    # The format is
    # 00 || 01 || PS || 00 || D
    # PS - padding string, at least 8 bytes of FF
    # D  - data.
    if not block.startswith(b"\x00\x01"):
        raise ValueError("Invalid PKCS#1 v1.5 padding")
    padding, sep, message = block[2:].partition(b"\x00")
    if not sep or len(padding) < 8 or set(padding) != {0xFF}:
        raise ValueError("Invalid PKCS#1 v1.5 padding")
    return message
