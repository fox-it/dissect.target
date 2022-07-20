import re
from datetime import datetime

from flow.record.fieldtypes import uri

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

re_field = re.compile(r"(.+)=(.+)")

AmcacheFileCreateRecord = TargetRecordDescriptor(
    "filesystem/windows/amcache/install",
    [
        ("datetime", "start_time"),
        ("datetime", "stop_time"),
        ("datetime", "created"),
        ("datetime", "modified"),
        ("datetime", "access"),
        ("uri", "path"),
        ("uri", "filename"),
        ("uri", "file_created"),
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
    ],
)

AmcacheArpCreateRecord = TargetRecordDescriptor(
    "filesystem/windows/amcache/install",
    [
        ("datetime", "start_time"),
        ("datetime", "stop_time"),
        ("datetime", "created"),
        ("datetime", "modified"),
        ("datetime", "access"),
        ("uri", "path"),
        ("uri", "filename"),
        ("uri", "arp_created"),
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
    ],
)


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

            for entry in created:
                yield AmcacheArpCreateRecord(
                    start_time=datetime.strptime(d["starttime"], "%m/%d/%Y %H:%M:%S"),
                    stop_time=datetime.strptime(d["stoptime"], "%m/%d/%Y %H:%M:%S"),
                    created=datetime.strptime(d["created"], "%m/%d/%Y %H:%M:%S"),
                    modified=datetime.strptime(d["modified"], "%m/%d/%Y %H:%M:%S"),
                    access=datetime.strptime(d["lastaccessed"], "%m/%d/%Y %H:%M:%S"),
                    path=uri.from_windows(d["path"]),
                    filename=uri.from_windows(str(f)),
                    arp_created=entry,
                    link_date=datetime.strptime(d["linkdate"], "%m/%d/%Y %H:%M:%S"),
                    size_of_image=d.get("sizeofimage"),
                    file_description=d.get("filedescription"),
                    size=d.get("size"),
                    digests=[None, d.get("id")[4:], None],  # remove leading zeros from the entry to create a sha1 hash
                    company_name=d.get("companyname"),
                    binary_type=d.get("binarytype"),
                    bin_product_version=d.get("binproductversion"),
                    bin_file_version=d.get("binfileversion"),
                    filesize=d.get("filesize"),
                    pe_image=d.get("peimagetype"),
                    product_version=d.get("productversion"),
                    crc_checksum=d.get("crcchecksum"),
                    legal=d.get("legalcopyright"),
                    magic=d.get("magic"),
                    linker_version=d.get("linkerversion"),
                    product_name=d.get("productname"),
                    pe_subsystem=d.get("pesubsystem"),
                    longname=d.get("longname"),
                    pe_checksum=d.get("pechecksum"),
                    _target=self.target,
                )

            for entry in created:
                yield AmcacheFileCreateRecord(
                    start_time=datetime.strptime(d["starttime"], "%m/%d/%Y %H:%M:%S"),
                    stop_time=datetime.strptime(d["stoptime"], "%m/%d/%Y %H:%M:%S"),
                    created=datetime.strptime(d["created"], "%m/%d/%Y %H:%M:%S"),
                    modified=datetime.strptime(d["modified"], "%m/%d/%Y %H:%M:%S"),
                    access=datetime.strptime(d["lastaccessed"], "%m/%d/%Y %H:%M:%S"),
                    path=uri.from_windows(d["path"]),
                    file_created=entry,
                    filename=uri.from_windows(str(f)),
                    link_date=datetime.strptime(d["linkdate"], "%m/%d/%Y %H:%M:%S"),
                    size_of_image=d.get("sizeofimage"),
                    file_description=d.get("filedescription"),
                    size=d.get("size"),
                    digests=[None, d.get("id")[4:], None],  # remove leading zeros from the entry to create a sha1 hash
                    company_name=d.get("companyname"),
                    binary_type=d.get("binarytype"),
                    bin_product_version=d.get("binproductversion"),
                    bin_file_version=d.get("binfileversion"),
                    filesize=d.get("filesize"),
                    pe_image=d.get("peimagetype"),
                    product_version=d.get("productversion"),
                    crc_checksum=d.get("crcchecksum"),
                    legal=d.get("legalcopyright"),
                    magic=d.get("magic"),
                    linker_version=d.get("linkerversion"),
                    product_name=d.get("productname"),
                    pe_subsystem=d.get("pesubsystem"),
                    longname=d.get("longname"),
                    pe_checksum=d.get("pechecksum"),
                    _target=self.target,
                )
