from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.cstruct import cstruct
from dissect.util.ts import wintimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

bam_def = """
    struct entry {
        uint64 ts;
    };
    """
c_bam = cstruct().load(bam_def)

BamDamRecord = TargetRecordDescriptor(
    "windows/registry/bam",
    [
        ("datetime", "ts"),
        ("path", "path"),
    ],
)


class BamDamPlugin(Plugin):
    """Plugin for bam/dam registry keys."""

    KEYS = (
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\dam\\UserSettings",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings",
    )

    def check_compatible(self) -> None:
        if not len(list(self.target.registry.keys(self.KEYS))) > 0:
            raise UnsupportedPluginError("No bam or dam registry keys not found")

    @export(record=BamDamRecord)
    def bam(self) -> Iterator[BamDamRecord]:
        """Parse bam and dam registry keys.

        Yields BamDamRecords with fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The parsed timestamp.
            path (uri): The parsed path.
        """
        for reg_path in self.KEYS:
            for r in self.target.registry.keys(reg_path):
                for sub in r.subkeys():
                    for entry in sub.values():
                        if isinstance(entry.value, int):
                            continue

                        data = c_bam.entry(entry.value)
                        yield BamDamRecord(
                            ts=wintimestamp(data.ts),
                            path=self.target.fs.path(entry.name),
                            _target=self.target,
                        )
