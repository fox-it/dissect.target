from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.hypervisor import vmx

from dissect.target.containers.vmdk import VmdkContainer
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


class VmxLoader(Loader):
    """Load VMware virtual machine configuration (VMX) files.

    References:
        - https://docs.vmware.com/en/VMware-Workstation-Pro/17/com.vmware.ws.using.doc/GUID-A968EF50-BA25-450A-9D1F-F8A9DEE640E7.html
    """

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)
        self.vmx = vmx.VMX.parse(path.read_text())

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() in (".vmx", ".vmtx")

    def map(self, target: Target) -> None:
        for disk in self.vmx.disks():
            path = self.base_path.joinpath(disk)

            if not path.is_file():
                base, sep, snapshot_id = path.stem.rpartition("-")
                if sep and len(snapshot_id) == 6 and snapshot_id.isdigit():
                    # Probably a snapshot, try to load the parent disk
                    target.log.info(
                        "Disk not found but seems to be a snapshot, trying previous snapshots: %s", path.name
                    )

                    snapshot_num = int(snapshot_id)
                    missing = [path.name]
                    for i in range(snapshot_num - 1, -1, -1):
                        snapshot_disk = (
                            path.with_name(f"{base}{path.suffix}")
                            if i == 0
                            else path.with_name(f"{base}-{i:06d}{path.suffix}")
                        )
                        target.log.debug("Trying to load snapshot: %s", snapshot_disk.name)

                        if snapshot_disk.is_file():
                            target.log.warning(
                                "Missing disk(s) but continuing with found snapshot: %s (missing %s)",
                                snapshot_disk.name,
                                ", ".join(missing),
                            )
                            path = snapshot_disk
                            break

                        missing.append(snapshot_disk.name)
                    else:
                        target.log.error("Failed to find previous snapshot for disk: %s", path.name)
                        continue
                else:
                    target.log.error("Disk not found: %s", path.name)
                    continue

            try:
                target.disks.add(VmdkContainer(path))
            except Exception:
                target.log.exception("Failed to load VMDK: %s", disk)
