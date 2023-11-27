from io import BytesIO
from unittest import mock

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loaders.hyperv import HyperVLoader
from tests._utils import absolute_path


@pytest.mark.parametrize(
    "descriptor_dir, disk_dir",
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
def test_hyperv_loader_xml(descriptor_dir, disk_dir, target_bare):
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

    assert HyperVLoader.detect(gen1_xml_path)
    with mock.patch("dissect.target.container.open") as mocked_open:
        loader = HyperVLoader(gen1_xml_path)
        loader.map(target_bare)

        mocked_open.assert_called_with(vfs.path(f"{disk_dir}\\Default Generation 1.vhdx").resolve())

    assert HyperVLoader.detect(gen2_xml_path)
    with mock.patch("dissect.target.container.open") as mocked_open:
        loader = HyperVLoader(gen2_xml_path)
        loader.map(target_bare)

        mocked_open.assert_called_with(vfs.path(f"{disk_dir}\\Default Generation 2.vhdx").resolve())

    assert HyperVLoader.detect(gen1_vmcx_path)
    with mock.patch("dissect.target.container.open") as mocked_open:
        loader = HyperVLoader(gen1_vmcx_path)
        loader.map(target_bare)

        mocked_open.assert_called_with(vfs.path(f"{disk_dir}\\Default Generation 1.vhdx").resolve())

    assert HyperVLoader.detect(gen2_vmcx_path)
    with mock.patch("dissect.target.container.open") as mocked_open:
        loader = HyperVLoader(gen2_vmcx_path)
        loader.map(target_bare)

        mocked_open.assert_called_with(vfs.path(f"{disk_dir}\\Default Generation 2.vhdx").resolve())
