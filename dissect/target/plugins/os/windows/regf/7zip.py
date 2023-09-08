from flow.record.fieldtypes import path

from dissect.target.exceptions import RegistryError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

PanelPathRecord = TargetRecordDescriptor(
    "windows/registry/sevenzip/panelpath",
    [
        ("datetime", "ts"),
        ("path", "path"),
    ],
)


ArcHistoryRecord = TargetRecordDescriptor(
    "windows/registry/sevenzip/archistory",
    [
        ("datetime", "ts"),
        ("path", "path"),
    ],
)


PathHistoryRecord = TargetRecordDescriptor(
    "windows/registry/sevenzip/pathhistory",
    [
        ("datetime", "ts"),
        ("path", "path"),
    ],
)


CopyHistoryRecord = TargetRecordDescriptor(
    "windows/registry/sevenzip/copyhistory",
    [
        ("datetime", "ts"),
        ("path", "path"),
    ],
)


FolderHistoryRecord = TargetRecordDescriptor(
    "windows/registry/sevenzip/folderhistory",
    [
        ("datetime", "ts"),
        ("path", "path"),
    ],
)


class SevenZipPlugin(Plugin):
    KEY = "HKCU\\Software\\7-Zip"

    def check_compatible(self) -> None:
        if not len(list(self.target.registry.keys(self.KEY))) > 0:
            raise UnsupportedPluginError("7-Zip registry key not found")

    def parse_key(self, key, keyname, valuename, record):
        try:
            subkey = key.subkey(keyname)
            value = subkey.value(valuename).value
            for file_path in value.decode("utf-16-le").split("\x00"):
                if not file_path:
                    continue

                yield record(
                    ts=subkey.ts,
                    path=path.from_windows(file_path),
                    _target=self.target,
                )
        except RegistryError:
            pass

    @export(record=[PanelPathRecord, ArcHistoryRecord, PathHistoryRecord, CopyHistoryRecord, FolderHistoryRecord])
    def sevenzip(self):
        """Return 7-Zip history information from the registry.

        7-Zip is an open source file archiver. If the HKCU\\Software\\7-Zip registry key exists, it checks for
        additional registry keys, such as ArcHistory and FolderHistory. This might provide insight in which files have
        been archived by 7-Zip.

        References:
            - https://www.7-zip.org/
        """
        target = self.target
        for key in target.registry.keys(self.KEY):
            try:
                subkey = key.subkey("FM")
                value = subkey.value("PanelPath0").value
                yield PanelPathRecord(
                    ts=subkey.ts,
                    path=path.from_windows(value),
                    _target=self.target,
                )
            except RegistryError:
                pass

            for record in self.parse_key(key, "Compression", "ArcHistory", ArcHistoryRecord):
                yield record

            for record in self.parse_key(key, "Extraction", "PathHistory", PathHistoryRecord):
                yield record

            for record in self.parse_key(key, "FM", "CopyHistory", CopyHistoryRecord):
                yield record

            for record in self.parse_key(key, "FM", "FolderHistory", FolderHistoryRecord):
                yield record
