from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target import container
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target

RE_VOLUME_ID = re.compile(r"(?:file=)?([^:]+):([^,]+)")


class ProxmoxLoader(Loader):
    """Loader for Proxmox VM configuration files.

    Proxmox uses volume identifiers in the format of ``storage_id:volume_id``. The ``storage_id`` maps to a
    storage configuration in ``/etc/pve/storage.cfg``. The ``volume_id`` is the name of the volume within
    that configuration.

    This loader currently does not support parsing the storage configuration, so it will attempt to open the
    volume directly from the same directory as the configuration file, or from ``/dev/pve/`` (default LVM config).
    If the volume is not found, it will log a warning.
    """

    @staticmethod
    def detect(path: Path) -> bool:
        if path.suffix.lower() != ".conf":
            return False

        with path.open("rb") as fh:
            lines = fh.read(512).split(b"\n")
            needles = [b"cpu:", b"memory:", b"name:"]
            return all(any(needle in line for line in lines) for needle in needles)

    def map(self, target: Target) -> None:
        with self.path.open("rt") as fh:
            for line in fh:
                if not (line := line.strip()):
                    continue

                key, value = line.split(":", 1)
                value = value.strip()

                # https://pve.proxmox.com/wiki/Storage
                if (
                    key.startswith(("scsi", "sata", "ide", "virtio"))
                    and key[-1].isdigit()
                    and (match := RE_VOLUME_ID.match(value))
                ):
                    storage_id, volume_id = match.groups()

                    # TODO: parse the storage information from /etc/pve/storage.cfg
                    # For now, let's try a few assumptions
                    disk_path = None
                    if (path := self.base_path.joinpath(volume_id)).exists() or (
                        path := self.base_path.joinpath("/dev/pve/").joinpath(volume_id)
                    ).exists():
                        disk_path = path

                    if disk_path:
                        try:
                            target.disks.add(container.open(disk_path))
                        except Exception:
                            target.log.exception("Failed to open disk: %s", disk_path)
                    else:
                        target.log.warning("Unable to find disk: %s:%s", storage_id, volume_id)
