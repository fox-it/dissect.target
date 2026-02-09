from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.loaders.vmx import VmxLoader

if TYPE_CHECKING:
    from pathlib import Path


class VmwarevmLoader(VmxLoader):
    """Load ``*.vmwarevm`` folders from VMware Fusion."""

    def __init__(self, path: Path, **kwargs):
        super().__init__(next(path.glob("*.vmx")), **kwargs)

    @staticmethod
    def detect(path: Path) -> bool:
        return path.is_dir() and path.suffix.lower() == ".vmwarevm" and len(list(path.glob("*.vmx"))) == 1
