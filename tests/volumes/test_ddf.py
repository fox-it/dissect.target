from __future__ import annotations

import gzip

from dissect.target.containers.raw import RawContainer
from dissect.target.target import Target
from dissect.target.volumes.ddf import DdfVolumeSystem
from tests._utils import absolute_path


def test_ddf() -> None:
    with (
        gzip.open(absolute_path("_data/volumes/ddf/ddf-disk0.bin.gz"), "rb") as fh0,
        gzip.open(absolute_path("_data/volumes/ddf/ddf-disk1.bin.gz"), "rb") as fh1,
    ):
        assert DdfVolumeSystem.detect_volume(fh0)
        assert DdfVolumeSystem.detect_volume(fh1)

        sets = list(DdfVolumeSystem.open_all([fh0, fh1]))
        assert len(sets) == 1

        ddf = sets[0]

        # The backing disk should always be a list of all source disks, even for a single set.
        assert isinstance(ddf.disk, list)
        assert ddf.disk == [fh0, fh1]

        assert len(ddf.volumes) == 1
        volume = ddf.volumes[0]
        assert volume.size == ddf.ddf.configurations[0].virtual_disks[0].size

        # Volumes should also expose their backing disks as a list.
        assert isinstance(volume.disk, list)
        assert volume.disk == [fh0, fh1]


def test_ddf_source_volumes() -> None:
    """Opening from :class:`Volume` sources should collect their backing disks into the ``disk`` list."""
    with (
        gzip.open(absolute_path("_data/volumes/ddf/ddf-disk0.bin.gz"), "rb") as fh0,
        gzip.open(absolute_path("_data/volumes/ddf/ddf-disk1.bin.gz"), "rb") as fh1,
    ):
        disk0 = RawContainer(fh0)
        disk1 = RawContainer(fh1)

        t = Target()
        t.disks.add(disk0)
        t.disks.add(disk1)
        t.apply()

        assert len(t.filesystems) == 1
        assert t.fs.path("file.txt").read_text() == "wow it worked"
