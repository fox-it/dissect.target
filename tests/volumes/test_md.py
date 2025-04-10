from __future__ import annotations

import gzip

from dissect.target.containers.raw import RawContainer
from dissect.target.target import Target
from dissect.target.volumes.md import MdVolumeSystem
from tests._utils import absolute_path


def test_md() -> None:
    with gzip.open(absolute_path("_data/volumes/md/md-nested.bin.gz"), "rb") as fh:
        assert MdVolumeSystem.detect_volume(fh)

        sets = list(MdVolumeSystem.open_all([fh]))
        assert len(sets) == 1

        md = sets[0]
        assert len(md.volumes) == 1
        assert md.volumes[0].size == md.md.configurations[0].virtual_disks[0].size


def test_nested_md_lvm() -> None:
    with gzip.open(absolute_path("_data/volumes/md/md-nested.bin.gz"), "rb") as fh:
        container = RawContainer(fh)

        t = Target()
        t.disks.add(container)
        t.apply()

        assert len(t.filesystems) == 1
        assert t.fs.path("file.txt").read_text() == "wow it worked\n"
