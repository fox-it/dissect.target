from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING, Union, Iterator

from flow.record.fieldtypes import path

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from dissect.target import Target

re_field = re.compile(r"(.+)=(.+)")

COMMON_ELEMENTS = [
    ("datetime", "start_time"),
    ("datetime", "stop_time"),
    ("datetime", "created"),
    ("datetime", "modified"),
    ("datetime", "access"),
    ("path", "path"),
    ("path", "filename"),
    ("path", "create"),
    ("string", "size"),
    ("string", "magic"),
    ("string", "size_of_image"),
    ("string", "pe_checksum"),
    ("datetime", "link_date"),
    ("string", "linker_version"),
    ("string", "bin_file_version"),
    ("string", "bin_product_version"),
    ("string", "binary_type"),
    ("digest", "digests"),
    ("wstring", "file_version"),
    ("wstring", "company_name"),
    ("wstring", "file_description"),
    ("wstring", "legal"),
    ("string", "original_filename"),
    ("wstring", "product_name"),
    ("string", "product_version"),
    ("string", "pe_image"),
    ("string", "pe_subsystem"),
    ("string", "crc_checksum"),
    ("string", "filesize"),
    ("wstring", "longname"),
    ("string", "msi"),
]

AmcacheFileCreateRecord = TargetRecordDescriptor(
    "filesystem/windows/amcache/install/file_create",
    COMMON_ELEMENTS,
)

AmcacheArpCreateRecord = TargetRecordDescriptor(
    "filesystem/windows/amcache/install/arp_create",
    COMMON_ELEMENTS,
)


def _to_log_timestamp(timestamp: str) -> datetime:
    return datetime.strptime(timestamp, "%m/%d/%Y %H:%M:%S")


def create_record(
    description: Union[AmcacheFileCreateRecord, AmcacheArpCreateRecord],
    filename: str,
    dictionary: dict,
    create: str,
    target: Target,
) -> TargetRecordDescriptor:
    return description(
        start_time=_to_log_timestamp(dictionary.get("starttime")),
        stop_time=_to_log_timestamp(dictionary.get("stoptime")),
        created=_to_log_timestamp(dictionary.get("created")),
        modified=_to_log_timestamp(dictionary.get("modified")),
        access=_to_log_timestamp(dictionary.get("lastaccessed")),
        link_date=_to_log_timestamp(dictionary.get("linkdate")),
        path=path.from_windows(dictionary.get("path")),
        filename=path.from_windows(filename),
        create=path.from_windows(create),
        size_of_image=dictionary.get("sizeofimage"),
        file_description=dictionary.get("filedescription"),
        size=dictionary.get("size"),
        digests=[None, dictionary.get("id")[4:], None],  # remove leading zeros from the entry to create a sha1 hash
        company_name=dictionary.get("companyname"),
        binary_type=dictionary.get("binarytype"),
        bin_product_version=dictionary.get("binproductversion"),
        bin_file_version=dictionary.get("binfileversion"),
        filesize=dictionary.get("filesize"),
        pe_image=dictionary.get("peimagetype"),
        product_version=dictionary.get("productversion"),
        crc_checksum=dictionary.get("crcchecksum"),
        legal=dictionary.get("legalcopyright"),
        magic=dictionary.get("magic"),
        linker_version=dictionary.get("linkerversion"),
        product_name=dictionary.get("productname"),
        pe_subsystem=dictionary.get("pesubsystem"),
        longname=dictionary.get("longname"),
        pe_checksum=dictionary.get("pechecksum"),
        _target=target,
    )


class AmcacheInstallPlugin(Plugin):
    """Amcache install log plugin."""

    def __init__(self, target):
        super().__init__(target)
        self.logs = self.target.fs.path("sysvol/windows/appcompat/programs/install")

    def check_compatible(self):
        if not self.logs.exists():
            raise UnsupportedPluginError("No amcache install logs found")

    @export(record=[AmcacheArpCreateRecord, AmcacheFileCreateRecord])
    def amcache_install(self) -> Iterator[AmcacheArpCreateRecord, AmcacheFileCreateRecord]:
        """Return the contents of the Amcache install log.

        The log file contains the changes an installer performed on the system.
        These only get created when the executable is an installer.
        """
        for f in self.logs.iterdir():
            d = {}
            arp = []
            created = []
            for line in f.read_text("utf-16-le").splitlines():
                match = re_field.match(line.rstrip())
                if not match:
                    continue

                if match.group(1) == "FileCreate":
                    created.append(match.group(2))

                elif match.group(1) == "ArpCreate":
                    arp.append(match.group(2))

                else:
                    d[match.group(1).lower()] = match.group(2)

            filename = str(f)
            for arp_create in arp:
                yield create_record(
                    AmcacheArpCreateRecord, filename=filename, dictionary=d, create=arp_create, target=self.target
                )
            for file_create in created:
                yield create_record(
                    AmcacheFileCreateRecord, filename=filename, dictionary=d, create=file_create, target=self.target
                )
