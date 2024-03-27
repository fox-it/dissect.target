from __future__ import annotations

import gzip
import io
import logging
import os
import zlib
from itertools import cycle, islice
from pathlib import Path
from typing import BinaryIO, Optional, Sequence, Union

from dissect.util.stream import RangeStream, RelativeStream

from dissect.target.container import Container
from dissect.target.tools.utils import catch_sigpipe

log = logging.getLogger(__name__)


def find_xor_key(fh: io.BytesIO) -> bytes:
    """Find the XOR key for the firmware file by using known plaintext of zeros.

    File object ``fobj`` should be at the correct offset where it should decode to all zeroes (0x00).

    Arguments:
        fh: File-like object to read from.

    Returns:
        bytes: XOR key, zero bytes if no key is found.
    """
    key = bytearray()

    pos = fh.tell()
    buf = fh.read(32)
    fh.seek(pos)

    if pos % 512 == 0:
        xor_char = 0xFF
    else:
        fobj.seek(pos - 1)
        xor_char = ord(fh.read(1))

    for i, k_char in enumerate(buf):
        idx = (i + pos) & 0x1F
        key.append((xor_char ^ k_char ^ idx) & 0xFF)
        xor_char = k_char

    # align xor key
    koffset = 32 - (pos & 0x1F)
    key = islice(cycle(key), koffset, koffset + 32)
    return bytes(key)


class FortiFirmwareFile:
    """Fortinet firmware file, handles transparant decompression and deobfuscation of the firmware file."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.size = None

        # Check if the file is gzipped
        self.is_gzipped = False
        self.fh.seek(0)
        header = self.fh.read(4)
        if header.startswith(b"\x1f\x8b"):
            self.is_gzipped = True

            # Find the extra metadata behind the gzip compressed data
            # as a bonus we can also calculate the size of the firmware here
            dec = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
            self.fh.seek(0)
            self.size = 0
            while True:
                data = self.fh.read(io.DEFAULT_BUFFER_SIZE)
                if not data:
                    break
                d = dec.decompress(dec.unconsumed_tail + data)
                self.size += len(d)

            # Ignore the trailer data of the gzip file if we have any
            if dec.unused_data:
                self.fh.seek(-len(dec.unused_data), io.SEEK_END)
                self.trailer_offset = self.fh.tell()
                self.trailer_data = self.fh.read()
                logger.info("Found trailer offset: %d, data: %r", self.trailer_offset, self.trailer_data)
                self.fh = RangeStream(self.fh, 0, self.trailer_offset)

            self.fh.seek(0)
            self.fh = gzip.GzipFile(fileobj=self.fh)

        # Find the xor key based on known offsets where the firmware should decode to zero bytes
        for zero_offset in (0x30, 0x40, 0x400):
            self.fh.seek(zero_offset)
            xor_key = find_xor_key(self.fh)
            if xor_key.isalnum():
                self.xor_key = xor_key
                logger.info("Found key %r @ offset %s", self.xor_key, zero_offset)
                break
        else:
            self.xor_key = None
            logger.info("No xor key found")

        # Determine the size of the firmware file if we didn't calculate it yet
        if self.size is None:
            self.fh.seek(0, io.SEEK_END)
            self.size = self.fh.tell()

        logger.info("firmware size: %s", self.size)
        logger.info("key: %r", self.xor_key)
        logger.info("gzipped: %s", self.is_gzipped)
        self.fh.seek(0)

    def seek(self, offset, whence=io.SEEK_SET):
        return self.fh.seek(offset, whence)

    def read(self, n=-1):
        data = bytearray()

        while True:
            pos = self.fh.tell()
            buf = self.fh.read(io.DEFAULT_BUFFER_SIZE)
            if not buf:
                break

            if self.xor_key:
                if pos % 512 == 0:
                    xor_char = 0xFF
                else:
                    self.fh.seek(pos - 1)
                    xor_char = ord(self.fh.read(1))
                    self.fh.seek(pos + len(buf))

                for i, cur_char in enumerate(buf):
                    if (i + pos) % 512 == 0:
                        xor_char = 0xFF
                    idx = (i + pos) & 0x1F
                    data.append(((self.xor_key[idx] ^ cur_char ^ xor_char) - idx) & 0xFF)
                    xor_char = cur_char
            else:
                data.extend(buf)

            if n > 0 and len(data) >= n:
                break

        if n == -1:
            n = None
        return bytes(data[:n])


class FortiFirmwareContainer(Container):
    __type__ = "fortifw"

    def __init__(self, fh: BinaryIO | Path, *args, **kwargs):
        if not hasattr(fh, "read"):
            fh = fh.open("rb")

        # Open the firmware file
        self.ff = FortiFirmwareFile(fh)

        # seek to MBR
        self.fw = RelativeStream(self.ff, 0x200)
        super().__init__(self.fw, self.ff.size, *args, **kwargs)

    @staticmethod
    def detect_fh(fh: BinaryIO, original: list | BinaryIO) -> bool:
        return False

    @staticmethod
    def detect_path(path: Path, original: list | BinaryIO) -> bool:
        # all Fortinet firmware files end with `-FORTINET.out`
        return str(path).lower().endswith("-fortinet.out")

    def read(self, length: int) -> bytes:
        return self.fw.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.fw.seek(offset, whence)

    def tell(self) -> int:
        return self.fw.tell()

    def close(self) -> None:
        pass


@catch_sigpipe
def main(argv: Optional[Sequence[str]] = None) -> None:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Decompress and deobfuscate Fortinet firmware file to stdout.")
    parser.add_argument("file", type=argparse.FileType("rb"), help="Fortinet firmware file")
    parser.add_argument("--verbose", "-v", action="store_true", help="verbose output")
    args = parser.parse_args(argv)

    if args.verbose:
        logging.basicConfig(level=logging.INFO)

    ff = FortiFirmwareFile(args.file)
    while True:
        data = ff.read(io.DEFAULT_BUFFER_SIZE)
        if not data:
            break
        sys.stdout.buffer.write(data)


if __name__ == "__main__":
    main()
