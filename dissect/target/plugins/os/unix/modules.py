from dataclasses import dataclass
from typing import Iterator

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export, internal
from dissect.target.target import Target

ModuleRecord = TargetRecordDescriptor(
    "unix/module",
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
    def __init__(self, target: Target):
        super().__init__(target)
        self._module_paths = list(self.target.fs.path("/sys/module").iterdir())

    def check_compatible(self) -> bool:
        return len(self._module_paths) > 0

    def _iterate_modules(self) -> Iterator[Module]:
        for module_path in self._module_paths:
            if module_path.joinpath("initstate").exists():
                # Normally the holders folder should exist, however Acquire currently doesn't collect a folder if its empty
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
    def modules(self) -> Iterator[ModuleRecord]:
        """Return information about active kernel modules."""
        for module in self._iterate_modules():
            yield ModuleRecord(
                name=module.name,
                size=module.size,
                refcount=module.refcnt,
                used_by=module.used_by,
                source=module.path,
            )

    @export(output="yield")
    def lsmod(self) -> Iterator[str]:
        """Return information about active kernel modules in lsmod format"""
        yield f"{'Module ':<28} {'Size':<7}  Used by"
        for module in self._iterate_modules():
            yield f"{module.name:<28} {module.size:<7}  {module.refcnt} {','.join(module.used_by)}"
