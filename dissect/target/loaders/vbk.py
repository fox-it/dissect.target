from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import LoaderError
from dissect.target.filesystems.vbk import VbkFilesystem
from dissect.target.loader import Loader, find_loader
from dissect.target.loaders.raw import RawLoader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


RE_RAW_DISK = re.compile(r"(?:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})|(?:DEV__.+)")


class VbkLoader(Loader):
    """Load Veaam Backup (VBK) files."""

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)
        self.vbkfs = VbkFilesystem(path.open("rb"))
        self.loader = None

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".vbk"

    def map(self, target: Target) -> None:
        # We haven't really researched any of the VBK metadata yet, so just try some common formats
        root = self.vbkfs.path("/")
        if (base := next(root.glob("*"), None)) is None:
            raise LoaderError("Unexpected empty VBK filesystem")

        if not (candidates := [path for pattern in ("*.vmx", "*.vmcx") if (path := next(base.glob(pattern), None))]):
            # Try to look for raw disks
            if not (disks := [path for path in base.iterdir() if RE_RAW_DISK.match(path.name)]):
                # Dunno, just give up 🤷‍♂️ should've spent extra time staring at summary.xml
                raise LoaderError("Unsupported VBK structure")

            candidates.append(root.joinpath("+".join(map(str, disks))))

        # Try to find a loader
        for candidate in candidates:
            if (loader := find_loader(candidate, fallbacks=[RawLoader])) is not None:
                ldr = loader(candidate)
                ldr.map(target)

                # Store a reference to the loader if we successfully mapped
                self.loader = ldr

                break
        else:
            raise LoaderError("Unsupported VBK structure")
