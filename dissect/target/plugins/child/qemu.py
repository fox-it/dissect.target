from __future__ import annotations

from typing import TYPE_CHECKING

from defusedxml import ElementTree

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

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for domain in self.target.fs.path("/etc/libvirt/qemu").glob("*.xml"):
            try:
                name = ElementTree.fromstring(domain.read_bytes()).find("name").text
            except Exception as e:
                self.target.log.error("Failed to parse name from QEMU config: %s", domain)  # noqa: TRY400
                self.target.log.debug("", exc_info=e)
                name = None

            yield ChildTargetRecord(
                type=self.__type__,
                name=name,
                path=domain,
                _target=self.target,
            )
