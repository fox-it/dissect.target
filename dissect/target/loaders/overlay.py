from dissect.target.filesystems.overlay import OverlayFilesystem
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.loader import Loader
from dissect.target.target import Target


class OverlayLoader(Loader):
    """Load Podman OCI overlay filesystems."""

    def __init__(self, path: TargetPath, **kwargs):
        super().__init__(path.resolve(), **kwargs)

    @staticmethod
    def detect(path: TargetPath) -> bool:
        # path should be a folder

        if not path.is_dir():
            return False

        # with the following files
        for file in ["diff", "link", "lower", "work"]:  # "merged" is optional
            if not path.joinpath(file).exists():
                return False

        # parents should be
        if "containers/storage/overlay/" not in path.as_posix():
            return False

        return True

    def map(self, target: Target) -> None:
        target.filesystems.add(OverlayFilesystem(self.path))
