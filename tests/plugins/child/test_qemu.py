import pytest

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.child.qemu import QemuChildTargetPlugin
from tests.conftest import absolute_path


def test_compatible(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    with pytest.raises(UnsupportedPluginError):
        QemuChildTargetPlugin(target_linux).check_compatible()

    qemu_xml = absolute_path("_data/loaders/libvirt/qemu.xml")
    fs_linux.map_file("/etc/libvirt/qemu/qemu.xml", qemu_xml)
    QemuChildTargetPlugin(target_linux).check_compatible()


def test_list_children(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    qemu_xml = absolute_path("_data/loaders/libvirt/qemu.xml")
    fs_linux.map_file("/etc/libvirt/qemu/linux2022.xml", qemu_xml)
    fs_linux.map_file("/etc/libvirt/qemu/linux2024.xml", qemu_xml)

    child_plugin = QemuChildTargetPlugin(target_linux)

    children = list(child_plugin.list_children())

    assert len(children) == 2

    child = children[0]
    assert child.type == "qemu"
    assert child.path == "/etc/libvirt/qemu/linux2022.xml"
