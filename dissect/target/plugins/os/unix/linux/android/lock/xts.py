from __future__ import annotations

from dissect.fve.crypto import create_cipher
from dissect.util.stream import AlignedStream


# TODO: Perhaps this should be moved into dissect.fve
class XTSDecryptionStream(AlignedStream):
    def __init__(self, fh: AlignedStream, key: bytes, size: int | None = None, block_size: int = 4096):
        self.fh = fh
        self.key = key
        self.block_size = block_size

        super().__init__(size=size, align=block_size)

    def _decrypt_block(self, offset: int) -> bytes:
        self.fh.seek(offset * self.block_size)
        encrypted = self.fh.read(self.block_size)
        return create_cipher("aes-xts-256", self.key, sector_size=4096, iv_sector_size=4096).decrypt(encrypted, offset)

    def _read(self, offset: int, length: int) -> bytes:
        return b"".join(
            self._decrypt_block(block)
            for block in range(offset // self.block_size, (offset + length) // self.block_size)
        )
