import re
from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.loaders.vbk import VBKLoader
from dissect.target.plugin import ChildTargetPlugin


class VBKChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from VBK."""

    __type__ = "vbk"

    def check_compatible(self) -> None:
        if not isinstance(self.target._loader, VBKLoader):
            raise UnsupportedPluginError("Not an VBK File")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for _, _, files in self.target.fs.walk_ext("/"):
            for file in files:
                is_vmx = file.path.lower().endswith(".vmx")
                is_disk = re.match(r'.{8}-.{4}-.{4}-.{4}-.{12}', file.name)

                if is_vmx or is_disk:
                    yield ChildTargetRecord(
                        type=self.__type__,
                        path=file.path,
                        _target=self.target,
                    )
