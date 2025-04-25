from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

from dissect.target.loaders.libvirt import LibvirtLoader
from tests.conftest import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_libvirt_detection(target_bare: Target, tmp_path: Path) -> None:
    xml_file = tmp_path.joinpath("base")
    xml_file.write_text("not a libvirt file")

    assert LibvirtLoader.detect(xml_file) is False

    xml_file = tmp_path.joinpath("base.xml")
    xml_file.write_text("<domain>")
    assert LibvirtLoader.detect(xml_file) is False

    xml_file = tmp_path.joinpath("base.xml")
    xml_file.write_text("not a libvirt file")

    assert LibvirtLoader.detect(xml_file) is False

    qemu_xml = Path(absolute_path("_data/loaders/libvirt/qemu.xml"))

    assert LibvirtLoader.detect(qemu_xml)


@patch(f"{LibvirtLoader.__module__}.container.open")
def test_libvirt_map(mocked_container_open: Mock, target_bare: Target, fs_linux: VirtualFilesystem) -> None:
    fs_linux.map_file("/test.xml", absolute_path("_data/loaders/libvirt/qemu.xml"))
    fs_linux.map_file_fh("/var/lib/libvirt/images/linux2022.qcow2", None)
    fs_linux.map_file_fh("/second-disk.qcow2", None)
    target_bare.fs.mount("/", fs_linux)

    loader = LibvirtLoader(target_bare.fs.path("/test.xml"))
    loader.map(target_bare)

    assert mocked_container_open.call_count == 2
