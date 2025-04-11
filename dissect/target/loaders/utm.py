from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target import container
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


class UtmLoader(Loader):
    """Load UTM virtual machine files."""

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)
        config_path = self.absolute_path.joinpath("config.plist")
        self.config: dict = plistlib.loads(config_path.read_bytes())

    @staticmethod
    def detect(path: Path) -> bool:
        return path.is_dir() and path.suffix.lower() == ".utm" and path.joinpath("config.plist").is_file()

    def map(self, target: Target) -> None:
        data_dir = self.absolute_path.joinpath("Data")
        for drive in self.config.get("Drive", []):
            if drive.get("ImageType") != "Disk":
                continue

            path = data_dir.joinpath(drive["ImageName"])
            try:
                target.disks.add(container.open(path))
            except Exception:
                target.log.exception("Failed to load drive: %s", drive)
