from dataclasses import dataclass
from typing import Iterator, Optional

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export, internal
from dissect.target.target import Target

ModuleRecord = TargetRecordDescriptor(
    "linux/module",
    [
        ("string", "name"),
        ("varint", "size"),
        ("varint", "refcount"),
        ("stringlist", "modules_referred"),
        ("uri", "source"),
    ],
)


@dataclass
class Module:
    path: Optional[str] = None
    name: Optional[str] = None
    size: Optional[int] = None
    refcnt: Optional[int] = None
    modules_referred: Optional[list[str]] = None


class ModulePlugin(Plugin):
    def __init__(self, target: Target):
        super().__init__(target)
        self._module_paths = list(self.target.fs.glob("/sys/module/*"))

    def check_compatible(self) -> bool:
        return len(self._module_paths) > 0

    @internal
    def iterate_modules(self) -> Iterator[Module]:
        for module_path in self._module_paths:
            if self.target.fs.path(module_path + "/initstate").exists():
                module_folder = self.target.fs.path(module_path)
                module = Module(module_path, module_folder.name)
                module.size = int(module_folder.joinpath("coresize").read_text())
                module.refcnt = int(module_folder.joinpath("refcnt").read_text())
                if module_folder.joinpath(
                    "holders"
                ).exists():  # Normally the holders folder should exist, however Acquire doesn't acquire a folder if its empty
                    module.modules_referred = [item.name for item in module_folder.joinpath("holders").iterdir()]
                else:
                    module.modules_referred = []
                yield module

    @export(record=ModuleRecord)
    def modules(self) -> Iterator[ModuleRecord]:
        """Return information about active kernel modules."""
        for module in self.iterate_modules():
            yield ModuleRecord(
                name=module.name,
                size=module.size,
                refcount=module.refcnt,
                modules_referred=module.modules_referred,
                source=module.path,
            )

    @export(output="yield")
    def lsmod(self):
        """Return information about active kernel modules in lsmod format"""
        lsmod_output = f"{'Module ':<28} {'Size':<7}  Used by\n"
        for module in self.iterate_modules():
            lsmod_output += f"{module.name:<28} {module.size:<7}  {module.refcnt} {','.join(module.modules_referred)}\n"
        yield lsmod_output
