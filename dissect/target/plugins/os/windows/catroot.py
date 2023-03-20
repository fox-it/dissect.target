from asn1crypto import algos, core
from flow.record.fieldtypes import digest, uri

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

HINT_NEEDLE = b"\x1e\x08\x00H\x00i\x00n\x00t"
MD5_NEEDLE = b"\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05"
SHA1_NEEDLE = b"\x06\x05\x2b\x0e\x03\x02\x1a"
SHA_GENERIC_NEEDLE = b"\x06\x09\x08\x86\x48\x01\x65\x03\x04\x02"

CatrootRecord = TargetRecordDescriptor(
    "windows/catroot",
    [
        ("digest", "digest"),
        ("uri", "hint"),
        ("uri", "source"),
    ],
)


def findall(buf, needle):
    offset = 0
    while True:
        offset = buf.find(needle, offset)
        if offset == -1:
            break

        yield offset
        offset += 1


class CatrootPlugin(Plugin):
    """Catroot plugin.

    Parses catroot files for hashes and file hints.
    """

    def __init__(self, target):
        super().__init__(target)
        self.catrootdir = self.target.fs.path("sysvol/windows/system32/catroot")

    def check_compatible(self):
        if len(list(self.catrootdir.iterdir())) == 0:
            raise UnsupportedPluginError("No catroot dirs found")

    @export(record=CatrootRecord)
    def catroot(self):
        """Return the content of the catalog files in the CatRoot folder.

        A catalog file contains a collection of cryptographic hashes, or thumbprints. These files are generally used to
        verify the integrity of Windows operating system files, instead of per-file authenticode signatures.

        References:
            - https://www.thewindowsclub.com/catroot-catroot2-folder-reset-windows
            - https://docs.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files

        Yields CatrootRecords with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            digest (digest): The parsed digest.
            hint (uri): File hint, if present.
            source (uri): Source catroot file.
        """
        # So asn1crypt dies when parsing these files, so we kinda bruteforce it
        # Look for the object identifiers of various hash types, and parse from there
        # We don't do any further checking, just traverse according to a known structure
        # If an exception occurs, we're not looking at the right structure.
        for d in self.catrootdir.iterdir():
            if not d.is_dir():
                continue

            for f in d.iterdir():
                buf = f.open().read()

                for needle in [MD5_NEEDLE, SHA1_NEEDLE, SHA_GENERIC_NEEDLE]:
                    # There's an identifier early on in the file that specifies the hash type for this file
                    offset = buf.find(needle, 0, 100)
                    if offset == -1:
                        continue

                    try:
                        # Sanity check
                        algos.DigestAlgorithmId.load(buf[offset:])
                    except TypeError:
                        continue

                    for offset in findall(buf, needle):
                        try:
                            digestid = algos.DigestAlgorithmId.load(buf[offset:])
                            # 4 bytes before the digest type, a sequence starts
                            objseq = core.Sequence.load(buf[offset - 4 :])
                            # The second entry in the sequence is the digest string
                            hexdigest = objseq[1].native.encode("hex")

                            # Later versions of windows also have a file hint
                            # Try to find it
                            digestlen = len(digestid.contents)
                            hintoffset = buf.find(HINT_NEEDLE, offset + digestlen, offset + digestlen + 64)

                            filehint = None
                            if hintoffset != -1:
                                try:
                                    file_buf = buf[hintoffset + len(HINT_NEEDLE) + 6 :]
                                    # There's an INTEGER after the Hint BMPString of size 6
                                    filehint = core.OctetString.load(file_buf).native.decode("utf-16-le")
                                except Exception:  # noqa
                                    pass

                            fdigest = digest()
                            if len(hexdigest) == 32:
                                fdigest.md5 = hexdigest
                            elif len(hexdigest) == 40:
                                fdigest.sha1 = hexdigest
                            elif len(hexdigest) == 64:
                                fdigest.sha256 = hexdigest

                            yield CatrootRecord(
                                digest=fdigest,
                                hint=uri.from_windows(filehint) if filehint else None,
                                source=str(f),
                                _target=self.target,
                            )
                        except Exception:  # noqa
                            continue
