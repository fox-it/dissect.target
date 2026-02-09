from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

ModuleRecord = TargetRecordDescriptor(
    "linux/module",
    [
        ("string", "name"),
        ("varint", "size"),
        ("varint", "refcount"),
        ("string[]", "used_by"),
        ("path", "source"),
    ],
)


@dataclass
class Module:
    path: str
    name: str
    size: int
    refcnt: int
    used_by: list[str]


class ModulePlugin(Plugin):
    """Linux volatile kernel ``/sys/module`` plugin."""

    def __init__(self, target: Target):
        super().__init__(target)
        self._module_base_path = self.target.fs.path("/sys/module")

    def check_compatible(self) -> bool:
        if not self._module_base_path.is_dir() or not next(self._module_base_path.iterdir(), None):
            raise UnsupportedPluginError("No module paths found.")

    def _iterate_modules(self) -> Iterator[Module]:
        for module_path in self._module_base_path.iterdir():
            if module_path.joinpath("initstate").exists():
                holders = []
                if (holders_path := module_path.joinpath("holders")).exists():
                    holders = [item.name for item in holders_path.iterdir()]
                yield Module(
                    module_path,
                    module_path.name,
                    int(module_path.joinpath("coresize").read_text()),
                    int(module_path.joinpath("refcnt").read_text()),
                    holders,
                )

    @export(record=ModuleRecord)
    def sysmodules(self) -> Iterator[ModuleRecord]:
        """Return information about active kernel modules."""
        for module in self._iterate_modules():
            yield ModuleRecord(
                name=module.name,
                size=module.size,
                refcount=module.refcnt,
                used_by=module.used_by,
                source=module.path,
                _target=self.target,
            )

    @export(output="yield")
    def lsmod(self) -> Iterator[str]:
        """Return information about active kernel modules in lsmod format."""
        yield f"{'Module ':<28} {'Size':<7}  Used by"
        for module in self._iterate_modules():
            yield f"{module.name:<28} {module.size:<7}  {module.refcnt} {','.join(module.used_by)}"
