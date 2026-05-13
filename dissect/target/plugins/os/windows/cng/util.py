from __future__ import annotations

import hashlib

from dissect.cstruct import u32


def derive_key_hash(name: str) -> str:
    """Derive the pseudo-MD5 hash ``NCryptOpenKey`` calculates when creating a new CNG key."""
    digest = hashlib.md5((name.lower() + "\0").encode("utf-16-le")).digest()
    chunks = [u32(digest[i * 4 : (i + 1) * 4]) for i in range(4)]
    return "".join(f"{chunk:08x}" for chunk in chunks)
