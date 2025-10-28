from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator


class VirtuozzoChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from Virtuozzo container's root.

    Virtuozzo containers are by default registered in the folder ``vz/root/$VEID``,
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

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for container in self.target.fs.path(self.PATH).iterdir():
            name = None
            try:
                if (vm_config := self.target.fs.path(self.CONFIG_PATH).joinpath(f"{container.name}.conf")).exists():
                    with vm_config.open("rt") as fh:
                        for line in fh:
                            if not (line := line.strip()):
                                continue

                            key, _, value = line.partition("=")
                            if key == "NAME":
                                name = value.strip('"')
                                break
            except Exception as e:
                self.target.log.exception("Failed to parse NAME from Virtuozzo config: %s", container)
                self.target.log.debug("", exc_info=e)

            yield ChildTargetRecord(
                type=self.__type__,
                name=name,
                path=container,
                _target=self.target,
            )
