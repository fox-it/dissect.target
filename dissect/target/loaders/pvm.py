from pathlib import Path

from dissect.target.loaders.pvs import PvsLoader


class PvmLoader(PvsLoader):
    """Parallels VM directory (.pvm)."""

    def __init__(self, path: Path, **kwargs):
        super().__init__(path.joinpath("config.pvs"))

    @staticmethod
    def detect(path: Path) -> bool:
        return path.is_dir() and path.suffix.lower() == ".pvm" and path.joinpath("config.pvs").exists()
