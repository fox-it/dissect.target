from __future__ import annotations

from typing import TYPE_CHECKING, Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


class Remote(ChildTargetPlugin):
    """Child target plugin that yields from remote broker."""

    __type__ = "remote"

    PATH = "/remote/data/children.txt"
    FOLDER = "/remote/children"

    def __init__(self, target: Target):
        super().__init__(target)

    def check_compatible(self) -> None:
        if not self.target.fs.path(self.PATH).exists():
            raise UnsupportedPluginError("No remote children.txt file found.")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        hosts = self.target.fs.path(self.PATH).read_text(encoding="utf-8").split("\n")
        for index, host in enumerate(hosts):
            yield ChildTargetRecord(type=self.__type__, path=f"{self.FOLDER}/child{index}.txt", _target=self.target)
