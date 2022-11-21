from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.loaders.dir import DirLoader, find_dirs, map_dirs

if TYPE_CHECKING:
    from dissect.target import Target


class VirtuozzoLoader(DirLoader):
    @staticmethod
    def detect(path: Path) -> bool:
        # /
        #   etc/
        #   var/
        #   vz/
        #       root/
        #           <container-uuid>
        #           <container-uuid>
        os_type, dirs = find_dirs(path)
        if os_type == "linux":
            for dir_path in dirs:
                if dir_path.joinpath("vz/root").exists():
                    return True
        return False

    def map(self, target: Target) -> None:
        # FIXME map multipe targets and test hostname plugin
        ve_root = self.path.joinpath("vz/root")
        if ve_root.exists():
            vz_containers = [p.name for p in ve_root.iterdir()]
            for container in vz_containers:
                target.path = ve_root.joinpath(container)
                map_dirs(target, ve_root.joinpath(container))
