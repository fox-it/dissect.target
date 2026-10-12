"""Extract uncompressed vmlinux from a kernel image.

Reference:
    - https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux
"""

from __future__ import annotations

import bz2
import lzma
import zlib
from pathlib import Path

# (magic, decompressor). Streaming decompressors stop at the end of their own
# stream and ignore trailing kernel data / junk
_FORMATS = [
    (b"\x1f\x8b\x08", lambda b: zlib.decompressobj(31).decompress(b)),  # gzip
    (b"\xfd7zXZ\x00", lambda b: lzma.LZMADecompressor(lzma.FORMAT_XZ).decompress(b)),  # xz
    (b"BZh", lambda b: bz2.BZ2Decompressor().decompress(b)),  # bzip2
    (b"\x5d\x00\x00\x00", lambda b: lzma.LZMADecompressor(lzma.FORMAT_ALONE).decompress(b)),  # lzma
]


def unpack_kernel(data: bytes, min_size: int = 0x100000) -> bytes | None:
    """Return the first compressed blob that decompresses to >= min_size bytes, else None.

    min_size (default 1 MiB) rejects stray/coincidental magics in the boot stub;
    pass 0 to accept the literal first decompressible blob regardless of size.
    """
    for magic, decompress in _FORMATS:
        pos = data.find(magic)
        while pos != -1:
            try:
                out = decompress(data[pos:])
            except Exception:
                out = b""
            if len(out) >= min_size and b"Linux version " in out:
                return out
            pos = data.find(magic, pos + 1)
    return None


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Extract uncompressed vmlinux from a kernel image.")
    parser.add_argument("kernel_image", help="path to the kernel image (flatkc)")
    args = parser.parse_args()
    data = Path(args.kernel_image).read_bytes()
    out = unpack_kernel(data)
    if out is None:
        sys.exit("no compressed kernel blob found")
    sys.stdout.buffer.write(out)
