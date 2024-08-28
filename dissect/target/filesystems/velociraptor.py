from pathlib import Path
from urllib.parse import unquote

from dissect.target.filesystems.dir import DirectoryFilesystem


class VelociraptorDirectoryFilesystem(DirectoryFilesystem):
    __type__ = "velociraptor_dir"

    def __init__(self, path: Path, *args, **kwargs):
        super().__init__(path, *args, **kwargs)

    def _resolve_path(self, path) -> Path:
        return super()._resolve_path(unquote(path).replace(".", "%2E"))
