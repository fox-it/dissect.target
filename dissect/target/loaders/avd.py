from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from dissect.hypervisor.disk.qcow2 import QCow2

from dissect.target.containers.raw import RawContainer
from dissect.target.loader import Loader
from dissect.target.volume import Volume

log = logging.getLogger(__name__)
if TYPE_CHECKING:
    from dissect.target.target import Target


class AVDLoader(Loader):
    """Load an Android Virtual Device."""

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)
        self.avd_folder = path
        self.encryptionkey_path = self.avd_folder.joinpath("encryptionkey.img.qcow2")
        self.encryptionkey_backing_path = self.avd_folder.joinpath("encryptionkey.img")

        self.userdata_path = self.avd_folder.joinpath("userdata-qemu.img.qcow2")
        self.userdata_backing_path = self.avd_folder.joinpath("userdata-qemu.img")

        qemu_config_path = self.avd_folder.joinpath("hardware-qemu.ini")
        self.system_partition_path = None

        if qemu_config_path.exists():
            qemu_config = qemu_config_path.read_text(encoding="utf-8").splitlines()
            for line in qemu_config:
                if line.startswith("disk.systemPartition.initPath"):
                    _, _, system_partition_path = line.partition("=")
                    self.system_partition_path = Path(system_partition_path.strip())
                    if not self.system_partition_path.exists():
                        self.system_partition_path = None
                    break

    @staticmethod
    def detect(path: Path) -> bool:
        return path.is_dir() and path.name.endswith(".avd") and path.joinpath("AVD.conf").exists()

    def map(self, target: Target) -> None:
        if self.system_partition_path:
            container = RawContainer(self.system_partition_path.open("rb"))
            target.disks.add(container)

        metadata_partition_disk_fh = QCow2(
            fh=self.encryptionkey_path.open("rb"), backing_file=self.encryptionkey_backing_path.open("rb")
        ).open()
        userdata_fh = QCow2(fh=self.userdata_path.open("rb"), backing_file=self.userdata_backing_path.open("rb")).open()

        target.disks.add(RawContainer(metadata_partition_disk_fh))
        target.volumes.add(Volume(userdata_fh, 1, 0, userdata_fh.size, None, "userdata"))
