from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .ciphers import aes_decrypt, chacha20_crypt, rc4_crypt, rsa_public_decrypt, xor
from .kdf import kdf_7_4_x
from .keycarver import iter_raw_key_candidates
from .models import AesKey, ChaCha20Key, ChaCha20Seed, RC4Key
from .tools.extract_vmlinux import unpack_kernel

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from .models import FirmwareKey, RawKeyCandidate

logger = logging.getLogger(__name__)

KEY_LEN = 32
IV_LEN = 16

KNOWN_KEY_IV_OFFSETS = [(3, 1), (5, 2), (6, 3)]

KNOWN_PLAINTEXT_GZIP = bytes.fromhex("1f8b0800")
KNOWN_PLAINTEXT_RSA_DER = bytes.fromhex("3082010a 02820101")


def try_candidate_chacha20key(
    candidate: RawKeyCandidate, rootfs_header: bytes, rootfs_footer: bytes
) -> ChaCha20Key | None:
    raw_key = candidate.raw_key
    _rsa_blob = candidate.rsa_blob

    if len(raw_key) != KEY_LEN + IV_LEN:
        return None

    key = raw_key[:KEY_LEN]
    iv = raw_key[KEY_LEN : KEY_LEN + IV_LEN]
    result = chacha20_crypt(rootfs_header[:4], key, iv)
    if result.startswith(KNOWN_PLAINTEXT_GZIP):
        return ChaCha20Key(key=key, iv=iv)

    return None


def try_candidate_chacha20seed(
    candidate: RawKeyCandidate, rootfs_header: bytes, rootfs_footer: bytes
) -> ChaCha20Seed | None:
    raw_key = candidate.raw_key
    _rsa_blob = candidate.rsa_blob

    if len(raw_key) != KEY_LEN:
        return None

    # to decrypt pubkey, use offset_key=3, offset_iv=1
    key, iv = kdf_7_4_x(raw_key, offset_key=4, offset_iv=5)
    result = chacha20_crypt(rootfs_header[:4], key, iv)
    if result.startswith(KNOWN_PLAINTEXT_GZIP):
        logger.info(
            "Found valid ChaCha20 seed at vmlinuz offset %d, using derived key %s and iv %s",
            candidate.blob_offset,
            key.hex(),
            iv.hex(),
        )
        return ChaCha20Seed(key=raw_key, offset_key=4, offset_iv=5)

    return None


def try_candidate_aeskey(candidate: RawKeyCandidate, rootfs_header: bytes, rootfs_footer: bytes) -> AesKey | None:
    raw_key = candidate.raw_key
    rsa_blob = candidate.rsa_blob

    if len(raw_key) != KEY_LEN:
        return None

    for i, j in KNOWN_KEY_IV_OFFSETS:
        chacha20_key, chacha20_iv = kdf_7_4_x(raw_key, i, j)
        pubkey = chacha20_crypt(rsa_blob, chacha20_key, chacha20_iv)
        if pubkey.startswith(KNOWN_PLAINTEXT_RSA_DER):
            try:
                payload = rsa_public_decrypt(pubkey, rootfs_footer)
            except Exception:
                continue
            logger.info(
                "Found valid RSA key at vmlinuz offset %d, using ChaCha20 key %s at offset: %d",
                candidate.blob_offset,
                raw_key.hex(),
                candidate.key_offset,
            )
            # Try different offsets for key and iv within the RSA decrypted payload
            for key_offset in (0, 16, 32, 48, 64):
                for iv_offset in (0, 16, 32, 48, 64):
                    key = payload[key_offset : key_offset + KEY_LEN]
                    iv = payload[iv_offset : iv_offset + IV_LEN]
                    if len(iv) != IV_LEN or len(key) != KEY_LEN:
                        continue
                    decrypted_header = aes_decrypt(rootfs_header, key, iv)
                    if decrypted_header.startswith(KNOWN_PLAINTEXT_GZIP):
                        return AesKey(key=key, iv=iv)
    return None


def try_candidate_rc4key(candidate: RawKeyCandidate, rootfs_header: bytes, rootfs_footer: bytes) -> RC4Key | None:
    raw_key = candidate.raw_key
    rsa_blob = candidate.rsa_blob

    if len(raw_key) != KEY_LEN:
        return None

    # unmask the RSA public key using the raw key
    pubkey = xor(rsa_blob, raw_key)
    if not pubkey.startswith(KNOWN_PLAINTEXT_RSA_DER):
        return None

    try:
        signature = rsa_public_decrypt(pubkey, rootfs_footer)
    except Exception:
        return None
    logger.info(
        "Found valid RSA key at vmlinuz offset %d, using XOR key at offset: %d",
        candidate.blob_offset,
        candidate.key_offset,
    )
    rc4key = signature[-32:]
    logger.info("RC4 key: %s", rc4key.hex())

    # TRY different RC4 arguments here.
    for i_bits in (5, 3):
        for reset_j in (True, False):
            prefix = rc4_crypt(rootfs_header[:4], rc4key, i_bits=i_bits, reset_j=reset_j)
            if prefix.startswith(KNOWN_PLAINTEXT_GZIP):
                key = RC4Key(rc4key, i_bits=i_bits, reset_j=reset_j)
                logger.info("rootfs.gz is possibly encrypted with RC4: %s", key)
                return key
    return None


def fwkeys_from_flatkc_and_rootfs(flatkc: Path, rootfs: Path) -> Iterator[FirmwareKey]:
    flatkc_data = flatkc.read_bytes()
    rootfs_data = rootfs.read_bytes()

    vmlinux = unpack_kernel(flatkc_data)
    if vmlinux is None:
        logger.warning(
            "Failed to unpack kernel from %s (maybe not packed), falling back to original flatkc data", flatkc
        )
        vmlinux = flatkc_data

    rootfs_header = rootfs_data[:64]
    rootfs_footer = rootfs_data[-256:]

    for candidate in iter_raw_key_candidates(vmlinux, max_reclaim=1):
        for try_func in (
            try_candidate_chacha20key,
            try_candidate_chacha20seed,
            try_candidate_aeskey,
            try_candidate_rc4key,
        ):
            if key := try_func(candidate, rootfs_header, rootfs_footer):
                yield key
    return
