from dissect import cstruct
from dissect.util.ts import wintimestamp
from flow.record.fieldtypes import uri

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

c_bamdef = """
    struct entry {
        uint64 ts;
    };
    """
c_bam = cstruct.cstruct()
c_bam.load(c_bamdef)

BamDamRecord = TargetRecordDescriptor(
    "windows/registry/bam",
    [
        ("datetime", "ts"),
        ("uri", "path"),
    ],
)


class BamDamPlugin(Plugin):
    """Plugin for bam/dam registry keys."""

    KEYS = [
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\dam\\UserSettings",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings",
    ]

    def check_compatible(self):
        if not len(list(self.target.registry.keys(self.KEYS))) > 0:
            raise UnsupportedPluginError("No bam or dam registry keys not found")

    @export(record=BamDamRecord)
    def bam(self):
        """Parse bam and dam registry keys.

        Yields BamDamRecords with fields:
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
                            path=uri.from_windows(entry.name),
                            _target=self.target,
                        )
