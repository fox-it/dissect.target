from __future__ import annotations

import io
from collections import defaultdict
from typing import TYPE_CHECKING, BinaryIO, Callable

from dissect.util.stream import MappingStream

from dissect.target.helpers.scrape import Needle, find_needles, scrape_chunks
from dissect.target.plugin import Plugin, internal
from dissect.target.volume import EncryptedVolumeSystem, LogicalVolumeSystem, Volume

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.container import Container
    from dissect.target.helpers.record import TargetRecordDescriptor


class ScrapePlugin(Plugin):
    __namespace__ = "scrape"

    def check_compatible(self) -> None:
        pass

    def create_streams(
        self, *, encrypted: bool = True, lvm: bool = True, all: bool = False
    ) -> Iterator[tuple[Container | Volume, MappingStream]]:
        """Yields streams for all disks and volumes of a target.

        At the basis, each disk of a target is represented as a stream of itself. If the target has volumes, these are
        checked to be either encrypted or LVM volumes (if the respective flags are set). If so, that volume is replaced
        in the disk stream with a stream of the volume itself, or removed.

        In the case of encrypted volumes, the encrypted volume is replaced with the decrypted volume. This is done
        transparently on the disk stream level, so the consumer does not need to worry about the decryption process.

        In the case of LVM volumes (including any sort of RAID), the base volumes are removed from the disk stream,
        and a new stream will be yielded for each logical volume. This ensures that no unnecessary scraping is
        performed on base volumes of a logical volume, but only on the reconstructed logical volume.

        Args:
            encrypted: Whether to replace encrypted volumes for their decrypted counterpart.
            lvm: Whether to skip base volumes of LVM volumes and yield the logical volume itself.
            all: Whether to yield all disks and volumes, regardless of their type.

        Yields:
            A tuple containing the disk (or volume, in the case of an LVM volume) and a stream of that disk.
        """
        # Create a map of disk regions we want to scrape
        scrape_map = defaultdict(dict)

        # Start off by making a very simple `disk: {(offset, size): volume}` map for every volume
        # Spaces in between volumes are also added as disk regions
        offset = 0
        for disk in self.target.disks:
            for volume in disk.vs.volumes if disk.vs else []:
                if offset != volume.offset:
                    # There's data between the volumes, so add that from the disk
                    scrape_map[disk][(offset, volume.offset - offset)] = (disk, offset)
                    offset = volume.offset

                # Add the volume to the stream
                scrape_map[disk][(volume.offset, volume.size)] = (volume, 0)
                offset += volume.size

            # There's data after the volumes until the end of the disk
            # Coincidentally this also takes care of disks with no volumes
            if offset != disk.size:
                scrape_map[disk][(offset, disk.size - offset)] = (disk, offset)

        # Iterate over all volumes and add the decrypted variant of encrypted volumes
        for volume in self.target.volumes:
            if encrypted and isinstance(volume.vs, EncryptedVolumeSystem):
                if not all:
                    # Decrypted volumes have the encrypted volume as the disk
                    source_volume: Volume = volume.disk
                    source_disk = source_volume.disk

                    # Replace the encrypted volume region with the decrypted volume region
                    scrape_map[source_disk][(source_volume.offset, source_volume.size)] = (volume, 0)
                else:
                    # Add the encrypted volume separately to the map
                    scrape_map[volume][(0, volume.size)] = (volume, 0)

            if lvm and isinstance(volume.vs, LogicalVolumeSystem):
                if not all:
                    # Remove the base volumes from the map
                    for source_volume in volume.disk:
                        source_disk = source_volume.disk
                        del scrape_map[source_disk][(source_volume.offset, source_volume.size)]

                # Add the logical volumes to the map
                scrape_map[volume][(0, volume.size)] = (volume, 0)

        for disk, volumes in scrape_map.items():
            # If we ended up removing all regions from the disk, skip it
            # I.e. when a disk is fully occupied by an LVM volume
            if not volumes:
                continue

            size = 0
            stream = MappingStream()
            for (map_offset, map_size), (source, source_offset) in volumes.items():
                stream.add(map_offset, map_size, source, source_offset)
                size = max(size, map_offset + map_size)
            stream.size = size

            yield disk, stream

    @internal
    def find(
        self,
        needles: Needle | list[Needle],
        lock_seek: bool = True,
        block_size: int = io.DEFAULT_BUFFER_SIZE,
        progress: Callable[[Container | Volume, int, int], None] | None = None,
    ) -> Iterator[tuple[Container | Volume, MappingStream, Needle, int]]:
        """Yields needles and their offsets found in all disks and volumes of a target.

        Args:
            needles: The needle or list of needles to search for.
            lock_seek:  Whether the file position is maintained by the scraper or the consumer.
                        Setting this to ``False`` wil allow the consumer to seek the file pointer, i.e. to skip forward.
            block_size: The block size to use for reading from the byte stream.
            progress: A function to call with the current disk, offset and size of the stream.
        """
        for disk, stream in self.create_streams():
            for needle, offset in find_needles(
                stream,
                needles,
                lock_seek=lock_seek,
                block_size=block_size,
                progress=(lambda current, disk=disk, stream=stream: progress(disk, current, stream.size))
                if progress
                else None,
            ):
                yield disk, stream, needle, offset

    @internal
    def scrape_chunks_from_disks(
        self,
        chunk_parser: Callable[[Needle, bytes], Iterator[TargetRecordDescriptor]],
        needle_chunk_size_map: dict[Needle, int] | None = None,
        needle: Needle | None = None,
        chunk_size: int | None = None,
        chunk_reader: Callable[[BinaryIO, Needle, int, int], bytes] | None = None,
        block_size: int = io.DEFAULT_BUFFER_SIZE,
    ) -> Iterator[TargetRecordDescriptor]:
        """Yields records scraped from chunks found in ``target.disks``.

        Args:
            chunk_parser: A function to parse a chunk and yield records.
            needle_chunk_size_map: A dictionary with needle as keys and chunk sizes as values.
            needle: A single needle to search for.
            chunk_size: The size of the chunks to scrape, when providing a single needle.
            chunk_reader: A function to read a chunk from a byte stream for provided needle, offset and chunk size.
            block_size: The block size to use for reading from the byte stream.
        """

        if needle_chunk_size_map and (needle or chunk_size):
            raise ValueError("Either `needle_chunk_size_map` or both `needle` and `chunk_size` must be provided")

        if (needle and not chunk_size) or (not needle and chunk_size):
            raise ValueError("Both `needle` and `chunk_size` must be provided")
        else:
            needle_chunk_size_map = {needle: chunk_size}

        for disk in self.target.disks:
            disk.seek(0)
            yield from scrape_chunks(
                disk,
                needle_chunk_size_map=needle_chunk_size_map,
                chunk_parser=chunk_parser,
                chunk_reader=chunk_reader,
                block_size=block_size,
            )

    @internal
    def scrape_needles_from_disks(
        self,
        needle: Needle | None = None,
        needles: list[Needle] | None = None,
        block_size: int = io.DEFAULT_BUFFER_SIZE,
    ) -> Iterator[tuple[BinaryIO, bytes, int]]:
        """Yields ``(bytestream, needle, offset)`` tuples, scraped from ``target.disks``.

        Args:
            needles: A list of byte needles to search for.
            needle: A single byte needle to search for.
            block_size: The block size to use for reading from the byte stream.
        """

        if needle and needles:
            raise ValueError("Either `needles` values or a single `needle` value must be provided")
        elif not needle and not needles:
            raise ValueError("At least one needle value must be provided")

        if needle:
            needles = [needle]

        for disk in self.target.disks:
            disk.seek(0)
            for needle, offset in find_needles(disk, needles=needles, block_size=block_size):
                yield disk, needle, offset
