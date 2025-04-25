from __future__ import annotations

from typing import TYPE_CHECKING, Union, get_args

from dissect.target.exceptions import RegistryError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, alias, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.regutil import RegistryKey

PanelPathRecord = TargetRecordDescriptor(
    "application/productivity/sevenzip/panelpath",
    [
        ("datetime", "ts"),
        ("path", "path"),
    ],
)

ArcHistoryRecord = TargetRecordDescriptor(
    "application/productivity/sevenzip/archistory",
    [
        ("datetime", "ts"),
        ("path", "path"),
    ],
)

PathHistoryRecord = TargetRecordDescriptor(
    "application/productivity/sevenzip/pathhistory",
    [
        ("datetime", "ts"),
        ("path", "path"),
    ],
)

CopyHistoryRecord = TargetRecordDescriptor(
    "application/productivity/sevenzip/copyhistory",
    [
        ("datetime", "ts"),
        ("path", "path"),
    ],
)

FolderHistoryRecord = TargetRecordDescriptor(
    "application/productivity/sevenzip/folderhistory",
    [
        ("datetime", "ts"),
        ("path", "path"),
    ],
)

SevenZipRecord = Union[PanelPathRecord, ArcHistoryRecord, PathHistoryRecord, CopyHistoryRecord, FolderHistoryRecord]


class SevenZipPlugin(Plugin):
    """Windows 7-Zip GUI plugin."""

    KEY = "HKCU\\Software\\7-Zip"

    def check_compatible(self) -> None:
        if not self.target.has_function("registry") or not list(self.target.registry.keys(self.KEY)):
            raise UnsupportedPluginError("7-Zip registry key not found")

    def parse_key(
        self, key: RegistryKey, keyname: str, valuename: str, record: TargetRecordDescriptor
    ) -> Iterator[TargetRecordDescriptor]:
        try:
            subkey = key.subkey(keyname)
            value = subkey.value(valuename).value
            for file_path in value.decode("utf-16-le").split("\x00"):
                if not file_path:
                    continue

                yield record(
                    ts=subkey.ts,
                    path=self.target.fs.path(file_path),
                    _target=self.target,
                )
        except RegistryError:
            pass

    @export(record=get_args(SevenZipRecord))
    @alias("7zip")
    def sevenzip(self) -> Iterator[SevenZipRecord]:
        """Return 7-Zip GUI history information from the registry.

        7-Zip is an open source file archiver. If the HKCU\\Software\\7-Zip registry key exists, it checks for
        additional registry keys, such as ArcHistory and FolderHistory. This might provide insight in which files have
        been archived by the 7-Zip GUI.

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
                    path=self.target.fs.path(value),
                    _target=self.target,
                )
            except RegistryError:
                pass

            yield from self.parse_key(key, "Compression", "ArcHistory", ArcHistoryRecord)
            yield from self.parse_key(key, "Extraction", "PathHistory", PathHistoryRecord)
            yield from self.parse_key(key, "FM", "CopyHistory", CopyHistoryRecord)
            yield from self.parse_key(key, "FM", "FolderHistory", FolderHistoryRecord)
