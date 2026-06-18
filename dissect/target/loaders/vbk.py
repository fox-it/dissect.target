from __future__ import annotations

import re
from itertools import chain
from typing import TYPE_CHECKING

from dissect.target.exceptions import LoaderError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.filesystems.vbk import VbkFilesystem
from dissect.target.loader import MiddlewareLoader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


RE_RAW_DISK = re.compile(r"(?:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})|(?:DEV__.+)")


class VbkLoader(MiddlewareLoader):
    """Load Veaam Backup (VBK) files.

    References:
        - https://helpcenter.veeam.com/docs/backup/hyperv/backup_files.html?ver=120
    """

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)
        self.vbkfs = VbkFilesystem(path.open("rb"))
        self.loader = None

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".vbk"

    def prepare(self, target: Target) -> Path:
        # We haven't really researched any of the VBK metadata yet, so just try some common formats
        root = self.vbkfs.path("/")
        if (base := next(root.glob("*"), None)) is None:
            raise LoaderError("Unexpected empty VBK filesystem")

        if not (
            candidates := [path for pattern in ("*.vmx", "Config/*.vmcx") if (path := next(base.glob(pattern), None))]
        ):
            # Try to look for raw disks
            if not (disks := [path for path in base.iterdir() if RE_RAW_DISK.match(path.name)]):
                # Dunno, just give up 🤷‍♂️ should've spent extra time staring at summary.xml
                raise LoaderError("Unsupported VBK structure, use `-L raw` to manually inspect the VBK")

            candidates.append(root.joinpath("+".join(map(str, disks))))

        # We should only have one candidate at this point
        if len(candidates) > 1:
            raise LoaderError("Unsupported VBK structure, use `-L raw` to manually inspect the VBK")

        candidate = candidates[0]
        if candidate.suffix.lower() == ".vmcx":
            # For VMCX files we need to massage the file layout a bit
            vfs = VirtualFilesystem()
            vfs.map_file_entry(candidate.name, candidate)

            for entry in chain(base.glob("Ide*/*"), base.glob("Scsi*/*")):
                vfs.map_file_entry(entry.name, entry)

            candidate = vfs.path(candidate.name)

        return candidate
