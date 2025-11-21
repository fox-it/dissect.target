from __future__ import annotations

import io
from collections import defaultdict
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import MappingStream

from dissect.target.helpers.scrape import Needle, find_needles, scrape_chunks
from dissect.target.plugin import Plugin, internal
from dissect.target.volume import EncryptedVolumeSystem, LogicalVolumeSystem, Volume

if TYPE_CHECKING:
    import re
    from collections.abc import Callable, Iterator

    from dissect.target.container import Container
    from dissect.target.helpers.record import TargetRecordDescriptor


class ScrapePlugin(Plugin):
    __namespace__ = "scrape"

    def check_compatible(self) -> None:
        pass

    def create_streams(
        self, *, encrypted: bool = True, lvm: bool = True, all: bool = False
    ) -> Iterator[tuple[Container | Volume, list[tuple[int | MappingStream]]]]:
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
            A tuple containing the disk (or volume, in the case of an LVM volume), and a list of tuples containing the
            physical offset and associated stream of contiguous regions on the disk.
        """
        # Create a map of disk regions we want to scrape
        scrape_map = defaultdict(dict)

        # This map tracks where every "available" volume object is located
        # within the scrape_map structure
        # Format: {volume_obj: (map_key, region_key)}

        # This can be optimized by creating a graph of volumes, and performing a topological sort
        volume_region_map = {}

        # Build initial map from physical disks
        offset = 0
        for disk in self.target.disks:
            for volume in self._get_disk_vols(disk):
                if offset != volume.offset:
                    # We don't add gaps (source=disk) to the volume_region_map
                    # as they can't be dependencies.
                    scrape_map[disk][(offset, volume.offset - offset)] = (disk, offset)
                    offset = volume.offset

                # Add the volume to the scrape_map
                region_key = (volume.offset, volume.size)
                scrape_map[disk][region_key] = (volume, 0)

                # Add this partition to our index
                volume_region_map[volume] = (disk, region_key)

                offset += volume.size

            if offset != disk.size:
                scrape_map[disk][(offset, disk.size - offset)] = (disk, offset)

        # Collect all layered volumes
        encrypted_volumes = []
        lvm_volumes = []
        for volume in self.target.volumes:
            if encrypted and isinstance(volume.vs, EncryptedVolumeSystem):
                encrypted_volumes.append(volume)
            if isinstance(volume.vs, LogicalVolumeSystem):
                lvm_volumes.append(volume)

        # Iteratively process all layered volumes until none remain
        pending_lvm = lvm_volumes
        pending_encrypted = encrypted_volumes
        deleted_scrape_regions = set()

        while pending_lvm or pending_encrypted:
            processed_this_pass = False

            # Attempt to process pending LVM volumes
            for volume in list(pending_lvm):
                dependencies_met = True
                backing_regions_info = []  # List of (map_key, region_key)

                try:
                    for source_dev in volume.vs.fh:
                        backing_vol_obj = source_dev.fh

                        if backing_vol_obj not in volume_region_map:
                            dependencies_met = False
                            break

                        backing_regions_info.append(volume_region_map[backing_vol_obj])

                except (AttributeError, TypeError):
                    dependencies_met = False

                if dependencies_met:
                    if not all:
                        for map_key, region_key in backing_regions_info:
                            # Only delete the scrape_map region if it hasn't
                            # been deleted by another LV in this VG.
                            # This occurs when multiple LVs share the same backing PV.
                            key_to_delete = (map_key, region_key)
                            if key_to_delete not in deleted_scrape_regions:
                                del scrape_map[map_key][region_key]
                                deleted_scrape_regions.add(key_to_delete)

                    # Add the new LVM volume as a new "disk"
                    new_region_key = (0, volume.size)
                    scrape_map[volume][new_region_key] = (volume, 0)

                    # Add this new LV to our index
                    volume_region_map[volume] = (volume, new_region_key)

                    pending_lvm.remove(volume)
                    processed_this_pass = True

            # Attempt to process pending Encrypted volumes
            for volume in list(pending_encrypted):
                backing_vol_obj = None
                try:
                    backing_vol_obj = volume.vs.fh
                except (AttributeError, TypeError):
                    continue

                if backing_vol_obj in volume_region_map:
                    # Dependency is met!
                    map_key, region_key = volume_region_map[backing_vol_obj]

                    if not all:
                        # Remove encrypted region from scrape_map
                        del scrape_map[map_key][region_key]

                        # Reinsert the decrypted volume region
                        new_region_key = (region_key[0], volume.size)  # Same offset, new size
                        scrape_map[map_key][new_region_key] = (volume, 0)

                        # Add this new decrypted volume to our index
                        volume_region_map[volume] = (map_key, new_region_key)

                    else:
                        # Add the decrypted volume separately
                        new_region_key = (0, volume.size)
                        scrape_map[volume][new_region_key] = (volume, 0)
                        # Add this new decrypted volume to our index
                        volume_region_map[volume] = (volume, new_region_key)

                    pending_encrypted.remove(volume)
                    processed_this_pass = True

            #  Stalemate Check
            if not processed_this_pass and (pending_lvm or pending_encrypted):
                raise RuntimeError(
                    f"Could not resolve storage dependencies. "
                    f"Stuck with {len(pending_lvm)} LVM volumes and "
                    f"{len(pending_encrypted)} encrypted volumes."
                )

        # Generate streams from the scrape_map
        for disk, volumes in scrape_map.items():
            # If we ended up removing all regions from the disk, skip it
            # I.e. when a disk is fully occupied by an LVM volume
            if not volumes:
                continue

            # Create a stream for every contiguous region
            streams = []
            current_stream = None
            current_stream_start = 0
            current_stream_end = 0
            for (offset, size), (source, source_offset) in volumes.items():
                # Check for a break in contiguity or the very first item
                if not current_stream or offset != current_stream_end:
                    # If a stream is already being built, add it to the list
                    if current_stream:
                        streams.append((current_stream_start, current_stream))

                    # Start a new stream
                    current_stream = MappingStream()
                    current_stream_start = offset

                # Add the current region to the stream and update the end pointer
                current_stream.add(offset - current_stream_start, size, source, source_offset)
                current_stream_end = offset + size

            # Add the last remaining stream after the loop
            if current_stream:
                streams.append((current_stream_start, current_stream))

            yield disk, streams

    @internal
    def find(
        self,
        needles: Needle | list[Needle],
        lock_seek: bool = True,
        block_size: int = io.DEFAULT_BUFFER_SIZE,
        progress: Callable[[Container | Volume, int, int], None] | None = None,
    ) -> Iterator[tuple[Container | Volume, MappingStream, Needle, int, re.Match | None]]:
        """Yields needles, their offsets and an optional regex match found in all disks and volumes of a target.

        Args:
            needles: The needle or list of needles to search for.
            lock_seek:  Whether the file position is maintained by the scraper or the consumer.
                        Setting this to ``False`` wil allow the consumer to seek the file pointer, i.e. to skip forward.
            block_size: The block size to use for reading from the byte stream.
            progress: A function to call with the current disk, offset and size of the stream.
        """
        for disk, streams in self.create_streams():
            for physical_offset, stream in streams:
                for needle, offset, match in find_needles(
                    stream,
                    needles,
                    lock_seek=lock_seek,
                    block_size=block_size,
                    progress=(lambda current, disk=disk, stream=stream: progress(disk, current, stream.size))
                    if progress
                    else None,
                ):
                    yield disk, stream, needle, physical_offset + offset, match

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
    ) -> Iterator[tuple[BinaryIO, bytes, int, re.Match | None]]:
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
            for needle, offset, match in find_needles(disk, needles=needles, block_size=block_size):
                yield disk, needle, offset, match

    @internal
    def _get_disk_vols(self, disk: Container) -> Iterator[Volume]:
        """Yields all volumes for a given disk container.

        When the disk has an associated volume system, volumes are retrieved from there.
        When the disk is raw, volumes are retrieved from the target's volume list.

        Args:
            disk: The disk container to get volumes for.
        """
        if disk.vs:
            yield from sorted(disk.vs.volumes, key=lambda v: v.offset)
        else:
            for volume in sorted(self.target.volumes, key=lambda v: v.offset or 0):
                if volume.disk == disk and not volume.vs:
                    yield volume
