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
    """

    __type__ = "virtuozzo"

    PATH = "/vz/root"

    def check_compatible(self) -> None:
        if not self.target.fs.path(self.PATH).exists():
            raise UnsupportedPluginError("No Virtuozzo path found")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for container in self.target.fs.path(self.PATH).iterdir():
            yield ChildTargetRecord(
                type=self.__type__,
                path=container,
                _target=self.target,
            )
