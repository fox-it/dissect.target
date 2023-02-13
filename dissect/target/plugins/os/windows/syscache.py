from dissect.ntfs import ntfs
from flow.record.fieldtypes import uri

from dissect.target.exceptions import RegistryValueNotFoundError, UnsupportedPluginError
from dissect.target.helpers import regutil
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

SyscacheRecord = TargetRecordDescriptor(
    "windows/syscache/object",
    [
        ("datetime", "regf_mtime"),
        ("digest", "digests"),
        ("string", "program_id"),
        ("string", "file_id"),
        ("varint", "object_id"),
        ("varint", "object_lru"),
        ("varint", "usn_journal_id"),
        ("varint", "usn"),
        ("uri", "path"),
    ],
)


class SyscachePlugin(Plugin):
    """Plugin to parse Syscache.hve.

    Reference:
    - https://dfir.ru/2018/12/02/the-cit-database-and-the-syscache-hive/
    """

    def __init__(self, target):
        super().__init__(target)
        self.hive = regutil.HiveCollection()

        fpath = self.target.fs.path("sysvol/System Volume Information/Syscache.hve")
        if fpath.exists():
            self.hive.add(regutil.RegfHive(fpath))

    def check_compatible(self):
        if not len(self.hive) > 0:
            raise UnsupportedPluginError("Could not load Syscache.hve")

    @export(record=SyscacheRecord)
    def syscache(self):
        """Parse the objects in the ObjectTable from the Syscache.hve file."""

        # Try to get the system volume
        mft = None
        sysvol = self.target.fs.mounts["sysvol"]
        if sysvol.__fstype__ == "ntfs" or hasattr(sysvol, "ntfs"):  # Nasty TarLoader hack
            mft = sysvol.ntfs.mft

        # There's some other stuff here like an IndexTable and LruList
        # Don't think they're too significant, so just iterate over all objects.
        for key in self.hive.keys("DefaultObjectStore\\ObjectTable"):
            for subkey in key.subkeys():
                try:
                    ae_file_id = subkey.value("AeFileID").value.decode("utf-16-le").strip("\x00")
                except RegistryValueNotFoundError:
                    ae_file_id = None

                try:
                    ae_program_id = subkey.value("AeProgramID").value.decode("utf-16-le").strip("\x00")
                except RegistryValueNotFoundError:
                    ae_program_id = None

                try:
                    file_id = subkey.value("_FileId_").value
                except RegistryValueNotFoundError:
                    # Bail out
                    continue

                file_segment = file_id & ((1 << 48) - 1)

                path = None
                if mft:
                    try:
                        path = uri.from_windows("\\".join(["sysvol", mft.mft(file_segment).fullpath()]))
                    except ntfs.Error:
                        pass

                yield SyscacheRecord(
                    regf_mtime=subkey.ts,
                    digests=[None, ae_file_id[4:] if ae_file_id else None, None],
                    program_id=ae_program_id,
                    file_id=f"{file_segment}#{file_id >> 48}",
                    object_id=subkey.value("_ObjectId_").value,
                    object_lru=subkey.value("_ObjectLru_").value,
                    usn_journal_id=subkey.value("_UsnJournalId_").value,
                    usn=subkey.value("_Usn_").value,
                    path=path,
                    _target=self.target,
                )
