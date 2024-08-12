from __future__ import annotations

from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin


class QemuChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields all qemu domains from a kvm libvirt deamon"""

    __type__ = "qemu"

    def check_compatible(self) -> None:
        if not self.target.fs.path("/etc/libvirt/qemu").exists():
            raise UnsupportedPluginError("No libvirt qemu installation found.")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for domain in self.target.fs.path("/etc/libvirt/qemu").glob("*.xml"):
            yield ChildTargetRecord(type=self.__type__, path=domain)
