import stat

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.filesystem.walkfs import FilesystemRecord

SuidRecord = TargetRecordDescriptor(
    "filesystem/unix/suid",
    FilesystemRecord.target_fields,
)


class SuidPlugin(Plugin):
    def check_compatible(self):
        return self.target.has_function("walkfs") and self.target.os != "windows"

    @export(record=SuidRecord)
    def suid_binaries(self):
        """Return all SUID binaries.

        A SUID binary allows all users to run it with the permissions of its owner. This means that a
        SUID binary owned by the root user can be run with root privileges by any user. Such binaries can be leveraged
        by an adversary to perform privilege escalation.

        References:
            - https://steflan-security.com/linux-privilege-escalation-suid-binaries/
        """
        for record in self.target.walkfs():
            if record.mode & stat.S_ISUID:
                yield SuidRecord(
                    **record._asdict(),
                    _target=self.target,
                )
