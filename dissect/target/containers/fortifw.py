from __future__ import annotations

import gzip
import io
import logging
import zlib
from itertools import cycle, islice
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import AlignedStream, RangeStream, RelativeStream

from dissect.target.container import Container
from dissect.target.tools.utils import catch_sigpipe

if TYPE_CHECKING:
    from pathlib import Path

log = logging.getLogger(__name__)


def find_xor_key(fh: BinaryIO) -> bytes:
    """Find the XOR key for the firmware file by using known plaintext of zeros.

    File-like object ``fh`` must be seeked to the correct offset where it should decode to all zeroes (0x00).

    Arguments:
        fh: File-like object to read from.

    Returns:
        bytes: XOR key, note that the XOR key is not validated and may be incorrect.
    """
    key = bytearray()

    pos = fh.tell()
    buf = fh.read(32)
    fh.seek(pos)

    if pos % 512 == 0:
        xor_char = 0xFF
    else:
        fh.seek(pos - 1)
        xor_char = ord(fh.read(1))

    for i, k_char in enumerate(buf):
        idx = (i + pos) & 0x1F
        key.append((xor_char ^ k_char ^ idx) & 0xFF)
        xor_char = k_char

    # align xor key
    koffset = 32 - (pos & 0x1F)
    key = islice(cycle(key), koffset, koffset + 32)
    return bytes(key)


class FortiFirmwareFile(AlignedStream):
    """Fortinet firmware file, handles transparant decompression and deobfuscation of the firmware file."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.trailer_offset = None
        self.trailer_data = None
        self.xor_key = None
        self.is_gzipped = False

        size = None

        # Check if the file is gzipped
        self.fh.seek(0)
        header = self.fh.read(4)
        if header.startswith(b"\x1f\x8b"):
            self.is_gzipped = True

            # Find the extra metadata behind the gzip compressed data
            # as a bonus we can also calculate the size of the firmware here
            dec = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
            self.fh.seek(0)
            size = 0
            while True:
                data = self.fh.read(io.DEFAULT_BUFFER_SIZE)
                if not data:
                    break
                d = dec.decompress(dec.unconsumed_tail + data)
                size += len(d)

            # Ignore the trailer data of the gzip file if we have any
            if dec.unused_data:
                self.trailer_offset = self.fh.seek(-len(dec.unused_data), io.SEEK_END)
                self.trailer_data = self.fh.read()
                log.debug("Found trailer offset: %d, data: %r", self.trailer_offset, self.trailer_data)
                self.fh = RangeStream(self.fh, 0, self.trailer_offset)

            self.fh.seek(0)
            self.fh = gzip.GzipFile(fileobj=self.fh)

        # Find the xor key based on known offsets where the firmware should decode to zero bytes
        for zero_offset in (0x30, 0x40, 0x400):
            self.fh.seek(zero_offset)
            xor_key = find_xor_key(self.fh)
            if xor_key.isalnum():
                self.xor_key = xor_key
                log.info("Found key %r @ offset %s", self.xor_key, zero_offset)
                break
        else:
            log.info("No xor key found")

        # Determine the size of the firmware file if we didn't calculate it yet
        if size is None:
            size = self.fh.seek(0, io.SEEK_END)

        log.info("firmware size: %s", size)
        log.info("xor key: %r", self.xor_key)
        log.info("gzipped: %s", self.is_gzipped)
        self.fh.seek(0)

        # Align the stream to 512 bytes which simplifies the XOR deobfuscation code
        super().__init__(size=size, align=512)

    def _read(self, offset: int, length: int) -> bytes:
        self.fh.seek(offset)
        buf = self.fh.read(length)

        if not self.xor_key:
            return buf

        buf = bytearray(buf)
        xor_char = 0xFF
        for i, cur_char in enumerate(buf):
            if (i + offset) % 512 == 0:
                xor_char = 0xFF
            idx = (i + offset) & 0x1F
            buf[i] = ((self.xor_key[idx] ^ cur_char ^ xor_char) - idx) & 0xFF
            xor_char = cur_char

        return bytes(buf)


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
def main(argv: list[str] | None = None) -> None:
    import argparse
    import shutil
    import sys

    parser = argparse.ArgumentParser(description="Decompress and deobfuscate Fortinet firmware file to stdout.")
    parser.add_argument("file", type=argparse.FileType("rb"), help="Fortinet firmware file")
    parser.add_argument("--verbose", "-v", action="store_true", help="verbose output")
    args = parser.parse_args(argv)

    if args.verbose:
        logging.basicConfig(level=logging.INFO)

    ff = FortiFirmwareFile(args.file)
    shutil.copyfileobj(ff, sys.stdout.buffer)


if __name__ == "__main__":
    main()
