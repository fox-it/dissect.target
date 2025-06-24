from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator


class VirtuozzoChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from Virtuozzo container's root.

    Virtuozzo conatiners are by default registered in the folder ``vz/root/$VEID``,
    where VEID will be substituted with the actual container UUID.

    .. code-block::

        /
        etc/
        var/
        vz/
            root/
                <container-uuid>/
                <container-uuid>/

    References:
        - https://docs.virtuozzo.com/virtuozzo_hybrid_server_7_command_line_reference/managing-system/configuration-files.html
        - https://wiki.openvz.org/Man/ctid.conf.5
        - https://docs.virtuozzo.com/pdf/virtuozzo_hybrid_server_7_command_line_reference.pdf

    """

    __type__ = "virtuozzo"

    PATH = "/vz/root"
    CONFIG_PATH = "/etc/vz/conf"

    def check_compatible(self) -> None:
        if not self.target.fs.path(self.PATH).exists():
            raise UnsupportedPluginError("No Virtuozzo path found")

    def _get_child_name(self, vm_path: str) -> str | None:
        try:
            vm_config = self.target.fs.path(self.CONFIG_PATH).joinpath(f"{vm_path.name}.conf")

            if not vm_config.exists():
                return None

            with vm_config.open("rt") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("NAME="):
                        return line.split("=", 1)[1].strip('"')
        except Exception as e:
            self.target.log.exception("Failed parsing NAME from vm_path=%s", vm_path)
            self.target.log.debug("", exc_info=e)
        return None

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for container in self.target.fs.path(self.PATH).iterdir():
            yield ChildTargetRecord(
                name=self._get_child_name(container),
                type=self.__type__,
                path=container,
                _target=self.target,
            )
