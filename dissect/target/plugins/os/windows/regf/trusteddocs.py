from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.cstruct import cstruct
from dissect.util.ts import wintimestamp

from dissect.target.exceptions import RegistryKeyNotFoundError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import (
    RegistryRecordDescriptorExtension,
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import WindowsUserRecord, create_extended_descriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.regutil import RegistryKey

TrustedDocumentsRecord = create_extended_descriptor([RegistryRecordDescriptorExtension, UserRecordDescriptorExtension])(
    "windows/registry/trusteddocuments",
    [
        ("datetime", "ts_modified"),
        ("datetime", "ts_created"),
        ("datetime", "ts_enabled"),
        ("string", "application"),
        ("path", "document"),
        ("string", "state"),
        ("bytes", "raw"),
        ("path", "source"),
    ],
)

trustrecord_def = """
typedef QWORD FILETIME;

enum TRFLAG {
    EDITING_ENABLED     = 0x00000001
    MACROS_ENABLED      = 0x7fffffff
};

struct TrustRecordEntry {
    FILETIME            ts_created;
    QWORD               timezone_offset;
    DWORD               ts_enabled;
    TRFLAG              flag;
};
"""

c_trustrecord = cstruct().load(trustrecord_def)


def convert_time(time: int) -> float:
    """Return minute precision timestamp from DWORD time integer."""
    multiplier = 16505867190471736999  # E5109EC205D7BEA7
    return ((time << (64 + 29)) / multiplier) / 10_000_000


class TrustedDocumentsPlugin(Plugin):
    """Plugin to obtain Microsoft Office Trusted Document registry keys."""

    KEY = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office"

    def check_compatible(self) -> None:
        if not len(list(self.target.registry.key(self.KEY))) > 0:
            raise UnsupportedPluginError("No Trusted Document keys found")

    def _find_subkey(self, key: RegistryKey, subkey_name: str) -> Iterator[RegistryKey]:
        try:
            searched_key = key.subkey(subkey_name)
            if subkeys := searched_key.subkeys():
                yield from subkeys
            else:
                yield searched_key
        except RegistryKeyNotFoundError:
            pass

    def _iterate_keys(self) -> Iterator[tuple[WindowsUserRecord, str, RegistryKey]]:
        """Yields all Microsoft Office keys that contain a TrustRecords subkey."""
        for key in self.target.registry.keys(self.KEY):
            user = self.target.registry.get_user(key)
            for version_key in key.subkeys():
                for application_key in version_key.subkeys():
                    yield from (
                        (user, application_key.name, y)
                        for x in self._find_subkey(application_key, "Security")
                        for y in self._find_subkey(x, "TrustRecords")
                    )

    @export(record=TrustedDocumentsRecord)
    def trusteddocs(self) -> Iterator[TrustedDocumentsRecord]:
        """Return Microsoft Office TrustRecords registry keys for all Office applications.

        Microsoft uses Trusted Documents to cache whether the user enabled the editing and/or macros for that document.
        Therefore, this may reveal if macros have been enabled for a malicious Office document.

        Yields records based on the values within the TrustRecords registry keys.
        At least contains the following fields:

        .. code-block:: text

            application (string): Application name of the Office product that produced the TrustRecords registry key.
            document (path): Path to the document for which a TrustRecords entry is created.
            ts (datetime): The created time of the TrustRecord registry key.
            type (varint): Type of the value within the TrustRecords registry key.
            value (bytes): Value of the TrustRecords entry, which contains the information whether macros are enabled.

        References:
            - https://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html
            - https://github.com/DissectMalware/OfficeForensicTools/blob/master/trusted_documents.py
            - https://github.com/nmantani/PS-TrustedDocuments
        """
        for user, application, key in self._iterate_keys():
            for value in key.values():
                entry = c_trustrecord.TrustRecordEntry(value.value)
                yield TrustedDocumentsRecord(
                    ts_modified=key.ts,
                    ts_created=wintimestamp(entry.ts_created),
                    ts_enabled=convert_time(entry.ts_enabled),
                    application=application,
                    document=self.target.resolve(value.name),
                    state=entry.flag.name,
                    raw=value.value,
                    _key=key,
                    _user=user,
                    _target=self.target,
                )
