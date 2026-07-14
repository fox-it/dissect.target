"""Real-image integration tests for the scrape plugin.

Unlike :mod:`tests.plugins.scrape.test_scrape`, which builds synthetic volume hierarchies with
mocks, these tests assemble real :class:`Target` instances from gzipped disk-image fixtures and run
the scraper against them. This validates that layered volumes (RAID, LVM, LUKS) resolve to the
correct physical regions end-to-end.
"""

from __future__ import annotations

import gzip
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.containers.raw import RawContainer
from dissect.target.helpers import keychain
from dissect.target.helpers.scrape import find_needles
from dissect.target.plugins.scrape.scrape import ScrapePlugin
from dissect.target.target import Target
from dissect.target.volume import EncryptedVolumeSystem, LogicalVolumeSystem
from tests._utils import absolute_path

try:
    from dissect.target.volumes.luks import LUKSVolumeSystem

    HAS_LUKS = True
except ImportError:
    HAS_LUKS = False

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.util.stream import MappingStream

    from dissect.target.container import Container
    from dissect.target.volume import Volume

MARKER = b"wow it worked"

# Fixed passphrase used by tests/_tools/make_luks_lvm.sh to create the LUKS keyslot.
LUKS_LVM_PASSPHRASE = "password1234"
LUKS_LVM_FIXTURE = absolute_path("_data/volumes/luks_lvm/luks-lvm.bin.gz")


def _logical_volumes(target: Target) -> list[Volume]:
    return [vol for vol in target.volumes if isinstance(vol.vs, LogicalVolumeSystem)]


def _find_in_streams(
    streams: Iterator[tuple[Container | Volume, list[tuple[int, MappingStream]]]], needle: bytes
) -> list[tuple[Container | Volume, int]]:
    """Collect ``(disk, physical_offset)`` tuples for a needle across all given scrape streams."""
    hits = []
    for disk, disk_streams in streams:
        for physical_offset, stream in disk_streams:
            for _, offset, _ in find_needles(stream, [needle]):
                hits.append((disk, physical_offset + offset))
    return hits


def test_scrape_ddf_raid() -> None:
    """Scraping a 2-disk DDF RAID1 array should yield a reconstructed stream for the assembled volume."""
    with (
        gzip.open(absolute_path("_data/volumes/ddf/ddf-disk0.bin.gz"), "rb") as fh0,
        gzip.open(absolute_path("_data/volumes/ddf/ddf-disk1.bin.gz"), "rb") as fh1,
    ):
        t = Target()
        t.disks.add(RawContainer(fh0))
        t.disks.add(RawContainer(fh1))
        t.apply()
        t.add_plugin(ScrapePlugin)

        # The known marker should be found through the reconstructed array, which proves it was scraped
        # as its own stream. The scraper reports offsets in the reconstructed volume's own coordinate
        # space, so reading it back at that offset should land exactly on the marker.
        raid_hits = [
            (disk, offset)
            for disk, _, needle, offset, _ in t.scrape.find(MARKER)
            if needle == MARKER and isinstance(disk.vs, LogicalVolumeSystem)
        ]
        assert raid_hits
        for disk, offset in raid_hits:
            disk.seek(offset)
            assert disk.read(len(MARKER)) == MARKER


def test_scrape_md_nested_lvm() -> None:
    """Scraping an MD RAID disk with a nested LVM should find data through the reconstructed logical volume."""
    with gzip.open(absolute_path("_data/volumes/md/md-nested.bin.gz"), "rb") as fh:
        t = Target()
        t.disks.add(RawContainer(fh))
        t.apply()
        t.add_plugin(ScrapePlugin)

        # The marker is stored in the filesystem on the reconstructed logical volume. The reported
        # offset should point at the marker within that logical volume's own coordinate space.
        lv_hits = [
            (disk, offset)
            for disk, _, needle, offset, _ in t.scrape.find(MARKER)
            if needle == MARKER and isinstance(disk.vs, LogicalVolumeSystem)
        ]
        assert lv_hits
        for disk, offset in lv_hits:
            disk.seek(offset)
            assert disk.read(len(MARKER)) == MARKER


@pytest.mark.skipif(not HAS_LUKS, reason="requires dissect.fve")
def test_scrape_luks_lvm() -> None:
    """Scraping a LUKS-encrypted disk with a nested LVM should resolve decryption and the logical volume.

    Layout: disk (GPT) -> partition -> LUKS -> LVM -> ext2 -> file.txt. With the passphrase registered,
    the scraper should map the decrypted volume in place at the LUKS partition offset and expose the
    reconstructed logical volume as its own stream containing the marker.
    """
    with patch.object(keychain, "KEYCHAIN", []):
        keychain.register_key(keychain.KeyType.PASSPHRASE, LUKS_LVM_PASSPHRASE, provider=LUKSVolumeSystem.__type__)

        with gzip.open(LUKS_LVM_FIXTURE, "rb") as fh:
            t = Target()
            t.disks.add(RawContainer(fh))
            t.apply()
            t.add_plugin(ScrapePlugin)

            # The LUKS layer should have produced exactly one decrypted volume and one logical volume.
            encrypted = [vol for vol in t.volumes if isinstance(vol.vs, EncryptedVolumeSystem)]
            assert len(encrypted) == 1
            decrypted = encrypted[0]

            # The encrypted partition backing the decrypted volume sits at a non-zero offset on disk.
            partition = decrypted.vs.fhs[0]
            assert partition.offset > 0

            # With decryption but without LVM reconstruction, the marker is reachable in the decrypted
            # volume, mapped in place on the disk at the LUKS partition offset. The physical offset the
            # scraper reports should equal the partition offset plus the marker's offset within the
            # decrypted volume.
            decrypted_hits = _find_in_streams(t.scrape.create_streams(encrypted=True, lvm=False), MARKER)
            assert decrypted_hits
            for _, offset in decrypted_hits:
                assert offset >= partition.offset
                decrypted.seek(offset - partition.offset)
                assert decrypted.read(len(MARKER)) == MARKER

            # With LVM reconstruction, the marker is found through the reconstructed logical volume, and
            # the reported offset points at the marker within that logical volume.
            lv = _logical_volumes(t)[0]

            lv_offsets = [
                offset for disk, _, needle, offset, _ in t.scrape.find(MARKER) if needle == MARKER and disk is lv
            ]
            assert lv_offsets
            for offset in lv_offsets:
                lv.seek(offset)
                assert lv.read(len(MARKER)) == MARKER
