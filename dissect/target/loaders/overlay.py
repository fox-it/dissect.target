from dissect.target.filesystems.overlay import Overlay2Filesystem
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.loader import Loader
from dissect.target.target import Target


class Overlay2Loader(Loader):
    """Load overlay2 filesystems"""

    def __init__(self, path: TargetPath, **kwargs):
        super().__init__(path.resolve(), **kwargs)

    @staticmethod
    def detect(path: TargetPath) -> bool:
        # path should be a folder
        if not path.is_dir():
            return False

        # with the following three files
        for required_file in ["init-id", "parent", "mount-id"]:
            if not path.joinpath(required_file).exists():
                return False

        # and should have the following parent folders
        if "image/overlay2/layerdb/mounts/" not in path.as_posix():
            return False

        return True

    def map(self, target: Target) -> None:
        target.filesystems.add(Overlay2Filesystem(self.path))
