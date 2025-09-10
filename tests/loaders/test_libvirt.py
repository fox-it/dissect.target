from __future__ import annotations

from typing import TYPE_CHECKING, Callable
from unittest.mock import call, patch

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import open as loader_open
from dissect.target.loaders.libvirt import LibvirtLoader
from dissect.target.target import Target
from tests.conftest import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target]) -> None:
    """Test that we correctly use ``LibvirtLoader`` when opening a ``Target``."""
    vfs = VirtualFilesystem()
    vfs.map_file("/test.xml", absolute_path("_data/loaders/libvirt/qemu.xml"))
    vfs.map_file_fh("/var/lib/libvirt/images/linux2022.qcow2", None)
    vfs.map_file_fh("/second-disk.qcow2", None)

    path = vfs.path("/test.xml")
    with patch("dissect.target.container.open"), patch("dissect.target.target.Target.apply"):
        target = opener(path)
        assert isinstance(target._loader, LibvirtLoader)
        assert target.path == path


def test_loader(tmp_path: Path) -> None:
    """Test that ``LibvirtLoader`` works with local files, absolute and relative."""
    xml_file = tmp_path.joinpath("base")
    xml_file.write_text("not a libvirt file")

    assert LibvirtLoader.detect(xml_file) is False

    xml_file = tmp_path.joinpath("base.xml")
    xml_file.write_text("<domain>")
    assert LibvirtLoader.detect(xml_file) is False

    xml_file = tmp_path.joinpath("base.xml")
    xml_file.write_text("not a libvirt file")

    assert LibvirtLoader.detect(xml_file) is False

    vfs = VirtualFilesystem()
    vfs.map_file("/test.xml", absolute_path("_data/loaders/libvirt/qemu.xml"))
    vfs.map_file_fh("/var/lib/libvirt/images/linux2022.qcow2", None)
    vfs.map_file_fh("/second-disk.qcow2", None)

    loader = loader_open(vfs.path("/test.xml"))
    assert isinstance(loader, LibvirtLoader)

    with patch("dissect.target.container.open") as mock_container_open:
        t = Target()
        loader.map(t)

        assert len(t.disks) == 2
        assert mock_container_open.call_count == 2
        mock_container_open.assert_has_calls(
            [
                call(vfs.path("/var/lib/libvirt/images/linux2022.qcow2")),
                call(vfs.path("/second-disk.qcow2")),
            ]
        )
