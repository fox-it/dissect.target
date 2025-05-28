from __future__ import annotations

from typing import TYPE_CHECKING

from defusedxml import ElementTree as ET

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator


class QemuChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields all QEMU domains from a KVM libvirt deamon."""

    __type__ = "qemu"

    def check_compatible(self) -> None:
        if not self.target.fs.path("/etc/libvirt/qemu").exists():
            raise UnsupportedPluginError("No libvirt QEMU installation found")

    def _get_child_name(self, vm_path: str) -> str | None:
        try:
            vm_path = self.target.fs.path(vm_path)
            config = ET.fromstring(vm_path.open().read_text())
            return config.find("name").text
        except Exception as e:
            self.target.log.exception("Failed parsing name from vm_path=%s", vm_path)
            self.target.log.debug("", exc_info=e)
        return None

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for domain in self.target.fs.path("/etc/libvirt/qemu").glob("*.xml"):
            yield ChildTargetRecord(name=self._get_child_name(domain), type=self.__type__, path=domain)
