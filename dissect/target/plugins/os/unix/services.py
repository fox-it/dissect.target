import re

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

LinuxServiceRecord = TargetRecordDescriptor(
    "linux/service",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("string", "servicepath"),
        ("string", "servicevariables"),
    ],
)


class ServicePlugin(Plugin):
    PATHS = (
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    )

    def check_compatible(self):
        if (
            not any([self.target.fs.path(p).exists() for p in self.PATHS])
            and not self.target.fs.path("/etc/init.d").exists()
        ):
            raise UnsupportedPluginError("No supported service directories found")

    @export(record=LinuxServiceRecord)
    def services(self):
        """Return information about all installed services."""

        for systemd_path in self.PATHS:
            path = self.target.fs.path(systemd_path)
            if not path.exists() or not path.is_dir():
                continue

            for file_ in path.iterdir():
                if file_.name.endswith(".wants"):
                    continue
                elif file_.name.endswith(".requires"):
                    continue
                elif file_.name.endswith(".d"):
                    continue

                fh = file_.open("rt")
                variables = ""

                try:
                    for line in fh:
                        line = line.strip().replace("\n", "")

                        if line[:1] == "[":
                            segment = re.sub(r"\[|\]", "", line)
                        elif line[:1] == ";" or line[:1] == "#" or line == "":
                            pass
                        else:
                            line = line.split("=", 1)
                            if "segment" in locals():
                                variables = f'{variables} {segment}_{line[0]}="{line[1]}" '
                            else:
                                variables = f"{variables} {line} "
                except UnicodeDecodeError:
                    break

                yield LinuxServiceRecord(
                    ts=file_.stat().st_mtime,
                    name=file_.name,
                    servicepath=str(file_),
                    servicevariables=variables,
                    _target=self.target,
                )

        path = self.target.fs.path("/etc/init.d")
        if path.exists():
            for file_ in path.iterdir():
                yield LinuxServiceRecord(
                    ts=file_.stat().st_mtime,
                    name=file_.name,
                    servicepath=str(file_),
                    servicevariables=None,
                    _target=self.target,
                )
