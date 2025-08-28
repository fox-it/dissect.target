from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING, Callable
from unittest import mock

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import open as loader_open
from dissect.target.loaders.hyperv import HyperVLoader
from dissect.target.target import Target
from tests._utils import absolute_path

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
    """Test that we correctly use ``HyperVLoader`` when opening a ``Target``."""
    for path in [
        absolute_path("_data/loaders/hyperv/B90AC31B-C6F8-479F-9B91-07B894A6A3F6.xml"),
        absolute_path("_data/loaders/hyperv/D351C151-DAC7-4042-B434-B72D522C1E4A.xml"),
        absolute_path("_data/loaders/hyperv/EC04F346-DB96-4700-AF5B-77B3C56C38BD.vmcx"),
        absolute_path("_data/loaders/hyperv/993F7B33-6057-4D1E-A1FE-A1A1D77BE974.vmcx"),
    ]:
        with mock.patch("dissect.target.target.Target.apply"):
            target = opener(path)
            assert isinstance(target._loader, HyperVLoader)
            assert target.path == path


@pytest.mark.parametrize(
    ("descriptor_dir", "disk_dir"),
    [
        # Disk next to descriptor file
        ("c:", "c:"),
        # Disk in "Virtual Hard Disks" directory, relative from descriptor file
        ("c:", "c:\\Virtual Hard Disks"),
        # Disk in "Virtual Hard Disks" directory, one directory up relative from descriptor file
        ("c:\\Virtual Machines", "c:\\Virtual Hard Disks"),
        # Disk in absolute location
        ("c:\\Virtual Machines", "c:\\Disks"),
    ],
)
def test_loader(descriptor_dir: str, disk_dir: str, target_bare: Target) -> None:
    """Test the Hyper-V loader with XML and VMCX descriptor files."""
    gen1_xml_filename = "B90AC31B-C6F8-479F-9B91-07B894A6A3F6.xml"
    gen2_xml_filename = "D351C151-DAC7-4042-B434-B72D522C1E4A.xml"
    gen1_vmcx_filename = "EC04F346-DB96-4700-AF5B-77B3C56C38BD.vmcx"
    gen2_vmcx_filename = "993F7B33-6057-4D1E-A1FE-A1A1D77BE974.vmcx"

    vfs = VirtualFilesystem(case_sensitive=False, alt_separator="\\")
    vfs.map_file(f"{descriptor_dir}\\{gen1_xml_filename}", absolute_path(f"_data/loaders/hyperv/{gen1_xml_filename}"))
    vfs.map_file(f"{descriptor_dir}\\{gen2_xml_filename}", absolute_path(f"_data/loaders/hyperv/{gen2_xml_filename}"))
    vfs.map_file(f"{descriptor_dir}\\{gen1_vmcx_filename}", absolute_path(f"_data/loaders/hyperv/{gen1_vmcx_filename}"))
    vfs.map_file(f"{descriptor_dir}\\{gen2_vmcx_filename}", absolute_path(f"_data/loaders/hyperv/{gen2_vmcx_filename}"))

    # Fake disks
    vfs.map_file_fh(f"{disk_dir}\\Default Generation 1.vhdx", BytesIO())
    vfs.map_file_fh(f"{disk_dir}\\Default Generation 2.vhdx", BytesIO())

    gen1_xml_path = vfs.path(f"{descriptor_dir}\\{gen1_xml_filename}")
    gen2_xml_path = vfs.path(f"{descriptor_dir}\\{gen2_xml_filename}")
    gen1_vmcx_path = vfs.path(f"{descriptor_dir}\\{gen1_vmcx_filename}")
    gen2_vmcx_path = vfs.path(f"{descriptor_dir}\\{gen2_vmcx_filename}")

    with mock.patch("dissect.target.container.open") as mock_container_open:
        loader = loader_open(gen1_xml_path)
        assert isinstance(loader, HyperVLoader)

        loader.map(target_bare)
        mock_container_open.assert_called_with(vfs.path(f"{disk_dir}\\Default Generation 1.vhdx").resolve())

    with mock.patch("dissect.target.container.open") as mock_container_open:
        loader = loader_open(gen2_xml_path)
        assert isinstance(loader, HyperVLoader)

        loader.map(target_bare)
        mock_container_open.assert_called_with(vfs.path(f"{disk_dir}\\Default Generation 2.vhdx").resolve())

    with mock.patch("dissect.target.container.open") as mock_container_open:
        loader = loader_open(gen1_vmcx_path)
        assert isinstance(loader, HyperVLoader)

        loader.map(target_bare)
        mock_container_open.assert_called_with(vfs.path(f"{disk_dir}\\Default Generation 1.vhdx").resolve())

    with mock.patch("dissect.target.container.open") as mock_container_open:
        loader = loader_open(gen2_vmcx_path)
        assert isinstance(loader, HyperVLoader)

        loader.map(target_bare)
        mock_container_open.assert_called_with(vfs.path(f"{disk_dir}\\Default Generation 2.vhdx").resolve())
