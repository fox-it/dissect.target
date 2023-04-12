from pathlib import Path

from dissect.target.loaders.vmx import VmxLoader


class VmwarevmLoader(VmxLoader):
    def __init__(self, path: Path, **kwargs):
        super().__init__(next(path.glob("*.vmx")))

    @staticmethod
    def detect(path: Path) -> bool:
        return path.is_dir() and path.suffix.lower() == ".vmwarevm" and len(list(path.glob("*.vmx"))) == 1
