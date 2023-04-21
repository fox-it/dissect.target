from pathlib import Path
from typing import Callable

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import Loader


class LogLoader(Loader):
    LOGS_DIRS = {
        "EvtxPlugin": "sysvol/windows/system32/winevt/logs",
        "EvtPlugin": "sysvol/windows/system32/config",
    }

    @staticmethod
    def detect(path: Path) -> bool:
        return False

    def appendix(self, plugin_method: Callable) -> dict[str, str]:
        return {"logs_dir": self.LOGS_DIRS[str(plugin_method.__self__.__class__.__name__)]}

    def _map_entry(self, entry: Path) -> str:
        logs_dir_key = entry.suffix[1:].capitalize()
        return str(Path(self.LOGS_DIRS[f"{logs_dir_key}Plugin"]).joinpath(entry.name)).lower()

    def map(self, target: Target) -> None:
        self.target = target
        vfs = VirtualFilesystem()
        for entry in self.path.parent.rglob(self.path.name):
            vfs.map_file(str(self._map_entry(entry)), str(entry))
        target.filesystems.add(vfs)
