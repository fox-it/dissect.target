import traceback
from typing import Iterator

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

InfoRecord = TargetRecordDescriptor(
    "target/info",
    [
        ("datetime", "last_activity"),
        ("datetime", "install_date"),
        ("net.ipaddress[]", "ips"),
        ("string", "os_family"),
        ("string", "os_version"),
        ("string", "architecture"),
        ("string[]", "language"),
        ("string", "timezone"),
        ("string[]", "disks"),
        ("string[]", "volumes"),
        ("string[]", "children"),
    ],
)


class InfoPlugin(Plugin):
    @export(record=InfoRecord)
    def info(self) -> Iterator[InfoRecord]:
        """Info plugin."""
        try:
            yield InfoRecord(
                hostname=self.target.hostname,
                domain=self.target.domain,
                ips=self.target.ips,
                os_family=self.target.os,
                os_version=self.target.version,
                architecture=self.target.architecture,
                language=self.target.language,
                timezone=self.target.timezone,
                install_date=self.target.install_date,
                last_activity=self.target.activity,
                disks=[{"type": d.__class__.__name__, "size": d.size} for d in self.target.disks],
                volumes=[{"name": v.name, "size": v.size, "fs": v.fs.__class__.__name__} for v in self.target.volumes],
                children=[{"type": c.type, "path": str(c.path)} for c in self.target.list_children()],
            )
        except NotImplementedError as e:
            filename, _, function, _ = traceback.extract_tb(e.__traceback__)[-1]
            self.target.log.warning("The function %s is not implemented in: %s", function, filename)
