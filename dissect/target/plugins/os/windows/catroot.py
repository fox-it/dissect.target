from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.esedb import EseDB
from flow.record.fieldtypes import digest

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.utils import findall
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

try:
    from asn1crypto.cms import ContentInfo
    from asn1crypto.core import Sequence

    HAS_ASN1 = True
except ImportError:
    HAS_ASN1 = False

HINT_NEEDLE = b"\x1e\x08\x00H\x00i\x00n\x00t"
PACKAGE_NAME_NEEDLE = b"\x06\n+\x06\x01\x04\x01\x827\x0c\x02\x01"
DIGEST_NEEDLES = {
    "md5": b"\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05",
    "sha1": b"\x06\x05\x2b\x0e\x03\x02\x1a",
    "sha_generic": b"\x06\x09\x08\x86\x48\x01\x65\x03\x04\x02",
    "sha256": b"\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00",
}


CatrootRecord = TargetRecordDescriptor(
    "windows/catroot",
    [
        ("digest", "digest"),
        ("string[]", "hints"),
        ("string", "catroot_name"),
        ("path", "source"),
    ],
)


def _get_package_name(sequence: Sequence) -> str:
    """Parse sequences within a sequence and return the 'PackageName' value if it exists."""
    for value in sequence.native.values():
        # Value is an ordered dict that contains a sequence on index 1
        inner_sequence = Sequence.load(value.get("1"))
        # Key value is stored at index 0, value at index 2
        if "PackageName" in inner_sequence[0].native:
            return inner_sequence[2].native.decode("utf-16-le").strip("\x00")
    return None


def find_package_name(hint_buf: bytes) -> str | None:
    """Find a sequence that contains the 'PackageName' key and return the value if present."""
    for hint_offset in findall(hint_buf, PACKAGE_NAME_NEEDLE):
        # 7, 6 or 5 bytes before the package_name needle, a sequence starts (starts with b"0\x82" or b"0\x81").
        for sequence_needle in [b"0\x82", b"0\x81"]:
            if (sequence_offset := hint_buf.find(sequence_needle, hint_offset - 8, hint_offset)) == -1:
                continue

            hint_sequence = Sequence.load(hint_buf[sequence_offset:])
            return _get_package_name(hint_sequence)
    return None


class CatrootPlugin(Plugin):
    """Catroot plugin.

    Parses catroot files for hashes and file hints.
    """

    __namespace__ = "catroot"

    def __init__(self, target: Target):
        super().__init__(target)
        self.catroot_dir = self.target.fs.path("sysvol/windows/system32/catroot")
        self.catroot2_dir = self.target.fs.path("sysvol/windows/system32/catroot2")

    def check_compatible(self) -> None:
        if not HAS_ASN1:
            raise UnsupportedPluginError("Missing asn1crypto dependency")

        if next(self.catroot2_dir.rglob("catdb"), None) is None and next(self.catroot_dir.rglob("*.cat"), None) is None:
            raise UnsupportedPluginError("No catroot files or catroot ESE databases found")

    @export(record=CatrootRecord)
    def files(self) -> Iterator[CatrootRecord]:
        """Return the content of the catalog files in the CatRoot folder.

        A catalog file contains a collection of cryptographic hashes, or thumbprints. These files are generally used to
        verify the integrity of Windows operating system files, instead of per-file authenticode signatures.

        At the moment, parsing catalog files is done on best effort. ``asn1crypto`` is not able to fully parse the
        ``encap_content_info``, highly likely because Microsoft uses its own format. Future research should result in
        a more resilient and complete implementation of the ``catroot.files`` plugin.

        References:
            - https://www.thewindowsclub.com/catroot-catroot2-folder-reset-windows
            - https://docs.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files

        Yields CatrootRecords with the following fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            digest (digest): The parsed digest.
            hints (string[]): File hints, if present.
            catroot_name (string): Catroot name.
            source (path): Source of the catroot record.
        """
        # As far as known, Microsoft uses its own implementation to store the digest in the
        # encap_content_info along with an optional file hint. Here we parse the digest values
        # ourselves by looking for the corresponding digest needles in the raw encap_content_info
        # data. Furthermore, we try to find the file hint if it is present in that same raw data.
        for file in self.catroot_dir.rglob("*.cat"):
            if not file.is_file():
                continue

            try:
                buf = file.read_bytes()

                # TODO: Parse other data in the content info
                content_info = ContentInfo.load(buf)["content"]

                digest_type = content_info["digest_algorithms"].native[0].get("algorithm")
                encap_contents = content_info["encap_content_info"].contents
                needle = DIGEST_NEEDLES[digest_type]

                digests = []
                offset = None
                for offset in findall(encap_contents, needle):
                    # 4 bytes before the digest type, a sequence starts
                    objseq = Sequence.load(encap_contents[offset - 4 :])
                    # The second entry in the sequence is the digest string
                    raw_digest = objseq[1].native
                    hexdigest = raw_digest.hex()

                    file_digest = digest()
                    if len(hexdigest) == 32:
                        file_digest.md5 = hexdigest
                    elif len(hexdigest) == 40:
                        file_digest.sha1 = hexdigest
                    elif len(hexdigest) == 64:
                        file_digest.sha256 = hexdigest

                    digests.append(file_digest)

                # Finding the hint in encap_content_info is on best effort. In most of the cases,
                # there is a key "PackageName" available. We first try to parse the corresponding
                # value if it is present. If this does not succeed, we might be dealing with catroot
                # files containing the "hint" needle.
                # If both methods do not result in a file hint, there is either no hint available or
                # the format is not yet known and therefore not supported.
                hints = []
                try:
                    if offset:
                        # As far as known, the PackageName data is only present in the encap_content_info
                        # after the last digest.
                        hint_buf = encap_contents[offset + len(needle) + len(raw_digest) + 2 :]

                        # First try to find to find the "PackageName" value, if it's present.
                        hint = find_package_name(hint_buf)
                        if hint:
                            hints.append(hint)

                    # If the package_name needle is not found or it's not present in the first 7 bytes of the hint_buf
                    # We are probably dealing with a catroot file that contains "hint" needles.
                    if not hints:
                        for hint_offset in findall(encap_contents, HINT_NEEDLE):
                            # Either 3 or 4 bytes before the needle, a sequence starts
                            bytes_before_needle = 3 if encap_contents[hint_offset - 3] == 48 else 4
                            name_sequence = Sequence.load(encap_contents[hint_offset - bytes_before_needle :])

                            hint = name_sequence[2].native.decode("utf-16-le").strip("\x00")
                            hints.append(hint)

                except Exception as e:
                    self.target.log.debug("", exc_info=e)

                # Currently, it is not known how the file hints are related to the digests. Therefore, each digest
                # is yielded as a record with all of the file hints found.
                # TODO: find the correlation between the file hints and the digests in catroot files.
                for file_digest in digests:
                    yield CatrootRecord(
                        digest=file_digest,
                        hints=hints,
                        catroot_name=file.name,
                        source=file,
                        _target=self.target,
                    )

            except Exception as e:
                self.target.log.error("An error occurred while parsing the catroot file %s: %s", file, e)  # noqa: TRY400
                self.target.log.debug("", exc_info=e)

    @export(record=CatrootRecord)
    def catdb(self) -> Iterator[CatrootRecord]:
        """Return the hash values present in the catdb files in the catroot2 folder.

        The catdb file is an ESE database file that contains the digests of the catalog files present on the system.
        This database is used to speed up the process of validating a Portable Executable (PE) file.

        Note: catalog files can include file hints, however these seem not to be present in the catdb files.

        References:
            - https://www.thewindowsclub.com/catroot-catroot2-folder-reset-windows
            - https://docs.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files

        Yields CatrootRecords with the following fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            digest (digest): The parsed digest.
            hints (string[]): File hints, if present.
            catroot_name (string): Catroot name.
            source (path): Source of the catroot record.
        """
        for ese_file in self.catroot2_dir.rglob("catdb"):
            with ese_file.open("rb") as fh:
                ese_db = EseDB(fh)

                for hash_type, table_name in [("sha256", "HashCatNameTableSHA256"), ("sha1", "HashCatNameTableSHA1")]:
                    try:
                        table = ese_db.table(table_name)
                    except KeyError as e:
                        self.target.log.warning("EseDB %s has no table %s", ese_file, table_name)
                        self.target.log.debug("", exc_info=e)
                        continue

                    for record in table.records():
                        file_digest = digest()

                        try:
                            setattr(file_digest, hash_type, record.get("HashCatNameTable_HashCol").hex())
                            catroot_names = record.get("HashCatNameTable_CatNameCol").decode().rstrip("|").split("|")
                        except Exception as e:
                            self.target.log.warning("Unable to parse catroot names for %s in %s", record, ese_file)
                            self.target.log.debug("", exc_info=e)
                            continue

                        for catroot_name in catroot_names:
                            yield CatrootRecord(
                                digest=file_digest,
                                hints=None,
                                catroot_name=catroot_name,
                                source=ese_file,
                                _target=self.target,
                            )
