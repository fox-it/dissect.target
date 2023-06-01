from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING, Union

from flow.record.fieldtypes import uri

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from dissect.target import Target

re_field = re.compile(r"(.+)=(.+)")

CREATED_URI_INDEX = 7
COMMON_ELEMENTS = [
    ("datetime", "start_time"),
    ("datetime", "stop_time"),
    ("datetime", "created"),
    ("datetime", "modified"),
    ("datetime", "access"),
    ("uri", "path"),
    ("uri", "filename"),
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

FileCreateElements = COMMON_ELEMENTS.copy()
FileCreateElements.insert(CREATED_URI_INDEX, ("uri", "file_created"))

AmcacheFileCreateRecord = TargetRecordDescriptor(
    "filesystem/windows/amcache/install",
    FileCreateElements,
)

ArpCreateElements = COMMON_ELEMENTS.copy()
ArpCreateElements.insert(CREATED_URI_INDEX, ("uri", "arp_created"))

AmcacheArpCreateRecord = TargetRecordDescriptor(
    "filesystem/windows/amcache/install",
    ArpCreateElements,
)


def _fill_common_descriptions(
    description: Union[AmcacheFileCreateRecord, AmcacheArpCreateRecord], filename: str, entry: dict, target: Target
) -> TargetRecordDescriptor:
    if description is AmcacheFileCreateRecord:
        entry_type = "file_created"
    elif description is AmcacheArpCreateRecord:
        entry_type = "arp_created"

    desc = description(
        start_time=datetime.strptime(entry["starttime"], "%m/%d/%Y %H:%M:%S"),
        stop_time=datetime.strptime(entry["stoptime"], "%m/%d/%Y %H:%M:%S"),
        created=datetime.strptime(entry["created"], "%m/%d/%Y %H:%M:%S"),
        modified=datetime.strptime(entry["modified"], "%m/%d/%Y %H:%M:%S"),
        access=datetime.strptime(entry["lastaccessed"], "%m/%d/%Y %H:%M:%S"),
        path=uri.from_windows(entry["path"]),
        filename=uri.from_windows(str(filename)),
        link_date=datetime.strptime(entry["linkdate"], "%m/%d/%Y %H:%M:%S"),
        size_of_image=entry.get("sizeofimage"),
        file_description=entry.get("filedescription"),
        size=entry.get("size"),
        digests=[None, entry.get("id")[4:], None],  # remove leading zeros from the entry to create a sha1 hash
        company_name=entry.get("companyname"),
        binary_type=entry.get("binarytype"),
        bin_product_version=entry.get("binproductversion"),
        bin_file_version=entry.get("binfileversion"),
        filesize=entry.get("filesize"),
        pe_image=entry.get("peimagetype"),
        product_version=entry.get("productversion"),
        crc_checksum=entry.get("crcchecksum"),
        legal=entry.get("legalcopyright"),
        magic=entry.get("magic"),
        linker_version=entry.get("linkerversion"),
        product_name=entry.get("productname"),
        pe_subsystem=entry.get("pesubsystem"),
        longname=entry.get("longname"),
        pe_checksum=entry.get("pechecksum"),
        _target=target,
    )
    setattr(desc, entry_type, entry)

    return desc


class AmcacheInstallPlugin(Plugin):
    """Amcache install log plugin."""

    def __init__(self, target):
        super().__init__(target)
        self.logs = self.target.fs.path("sysvol/windows/appcompat/programs/install")

    def check_compatible(self):
        if not self.logs.exists():
            raise UnsupportedPluginError("No amcache install logs found")

    @export(record=DynamicDescriptor(["uri"]))
    def amcache_install(self):
        """Return the contents of the Amcache install log."""
        for f in self.logs.iterdir():
            d = {}
            arp = []
            created = []
            for line in f.open().read().decode("utf-16-le").split("\r\n"):
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
            for entry in arp:
                yield _fill_common_descriptions(
                    AmcacheArpCreateRecord, filename=filename, entry=entry, target=self.target
                )
            for entry in created:
                yield _fill_common_descriptions(
                    AmcacheFileCreateRecord, filename=filename, entry=entry, target=self.target
                )
