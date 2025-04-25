from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

import dissect.util.ts as ts
from dissect.cstruct import cstruct

from dissect.target.helpers.record import TargetRecordDescriptor

if TYPE_CHECKING:
    from collections.abc import Iterator

DefenderQuarantineRecord = TargetRecordDescriptor(
    "filesystem/windows/defender/quarantine",
    [
        ("datetime", "ts"),
        ("bytes", "quarantine_id"),
        ("bytes", "scan_id"),
        ("varint", "threat_id"),
        ("string", "detection_type"),
        ("string", "detection_name"),
    ],
)

DefenderFileQuarantineRecord = TargetRecordDescriptor(
    "filesystem/windows/defender/quarantine/file",
    [
        ("datetime", "ts"),
        ("bytes", "quarantine_id"),
        ("bytes", "scan_id"),
        ("varint", "threat_id"),
        ("string", "detection_type"),
        ("string", "detection_name"),
        ("string", "detection_path"),
        ("datetime", "creation_time"),
        ("datetime", "last_write_time"),
        ("datetime", "last_accessed_time"),
        ("string", "resource_id"),
    ],
)

# Source: https://github.com/brad-sp/cuckoo-modified/blob/master/lib/cuckoo/common/quarantine.py#L188
# fmt: off
DEFENDER_QUARANTINE_RC4_KEY = [
    0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69, 0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23,
    0xB7, 0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC, 0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31,
    0xFD, 0x0F, 0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18, 0x27, 0x96, 0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C,
    0x9C, 0xBC, 0xE4, 0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8, 0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E,
    0xD6, 0x8D, 0xC9, 0x04, 0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58, 0xCB, 0x84, 0x7C, 0xA9, 0xFF,
    0xBE, 0x3C, 0x8A, 0x77, 0x52, 0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC, 0x1B, 0xC8, 0xF1, 0x0F,
    0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59, 0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19, 0x18, 0x18, 0xAF,
    0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D, 0x2C, 0x07, 0xE2, 0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E, 0xD8, 0xF6,
    0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29, 0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3, 0xDB,
    0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D, 0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE,
    0xD7, 0xDC, 0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12, 0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16, 0x4B,
    0x11, 0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6, 0x26, 0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B,
    0x83, 0x98, 0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36, 0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C,
    0xA4, 0xC3, 0xDD, 0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53
]
# fmt: on

defender_def = """
/* ======== Generic Windows ======== */
/* https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-win32_stream_id */

enum STREAM_ID {
    DATA                 = 0x00000001,
    EA_DATA              = 0x00000002,
    SECURITY_DATA        = 0x00000003,
    ALTERNATE_DATA       = 0x00000004,
    LINK                 = 0x00000005,
    PROPERTY_DATA        = 0x00000006,
    OBJECT_ID            = 0x00000007,
    REPARSE_DATA         = 0x00000008,
    SPARSE_BLOCK         = 0x00000009,
    TXFS_DATA            = 0x0000000A,
    GHOSTED_FILE_EXTENTS = 0x0000000B,
};

flag STREAM_ATTRIBUTES {
    STREAM_NORMAL_ATTRIBUTE                 = 0x00000000,
    STREAM_MODIFIED_WHEN_READ               = 0x00000001,
    STREAM_CONTAINS_SECURITY                = 0x00000002,
    STREAM_CONTAINS_PROPERTIES              = 0x00000004,
    STREAM_SPARSE_ATTRIBUTE                 = 0x00000008,
    STREAM_CONTAINS_GHOSTED_FILE_EXTENTS    = 0x00000010,
};

typedef struct _WIN32_STREAM_ID {
    STREAM_ID           StreamId;
    STREAM_ATTRIBUTES   StreamAttributes;
    QWORD               Size;
    DWORD               StreamNameSize;
    WCHAR               StreamName[StreamNameSize / 2];
} WIN32_STREAM_ID;

/* ======== Defender Specific ======== */

enum FIELD_IDENTIFIER : WORD {
    CQuaResDataID_File      = 0x02,
    CQuaResDataID_Registry  = 0x03,
    Flags                   = 0x0A,
    PhysicalPath            = 0x0C,
    DetectionContext        = 0x0D,
    Unknown                 = 0x0E,
    CreationTime            = 0x0F,
    LastAccessTime          = 0x10,
    LastWriteTime           = 0x11
};

enum FIELD_TYPE : WORD {
    STRING          = 0x1,
    WSTRING         = 0x2,
    DWORD           = 0x3,
    RESOURCE_DATA   = 0x4,
    BYTES           = 0x5,
    QWORD           = 0x6,
};

struct QuarantineEntryFileHeader {
    CHAR        MagicHeader[4];
    CHAR        Unknown[4];
    CHAR        _Padding[32];
    DWORD       Section1Size;
    DWORD       Section2Size;
    DWORD       Section1CRC;
    DWORD       Section2CRC;
    CHAR        MagicFooter[4];
};

struct QuarantineEntrySection1 {
    CHAR    Id[16];
    CHAR    ScanId[16];
    QWORD   Timestamp;
    QWORD   ThreatId;
    DWORD   One;
    CHAR    DetectionName[];
};

struct QuarantineEntrySection2 {
    DWORD   EntryCount;
    DWORD   EntryOffsets[EntryCount];
};

struct QuarantineEntryResource {
    WCHAR   DetectionPath[];
    WORD    FieldCount;
    CHAR    DetectionType[];
};

struct QuarantineEntryResourceField {
    WORD        Size;
    WORD        Identifier:12;
    FIELD_TYPE  Type:4;
    CHAR        Data[Size];
};
"""

c_defender = cstruct().load(defender_def)

STREAM_ID = c_defender.STREAM_ID
STREAM_ATTRIBUTES = c_defender.STREAM_ATTRIBUTES
FIELD_IDENTIFIER = c_defender.FIELD_IDENTIFIER


def rc4_crypt(data: bytes) -> bytes:
    """RC4 encrypt / decrypt using the Defender Quarantine RC4 Key."""
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + DEFENDER_QUARANTINE_RC4_KEY[i]) % 256
        tmp = sbox[i]
        sbox[i] = sbox[j]
        sbox[j] = tmp

    out = bytearray(len(data))
    i = 0
    j = 0
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        tmp = sbox[i]
        sbox[i] = sbox[j]
        sbox[j] = tmp
        val = sbox[(sbox[i] + sbox[j]) % 256]
        out[k] = val ^ data[k]

    return bytes(out)


def recover_quarantined_file_streams(fh: BinaryIO, filename: str) -> Iterator[tuple[str, bytes]]:
    """Recover the various data streams present in a quarantined file.

    Yields tuples of the output filename and the corresponding output data.
    """

    buf = BytesIO(rc4_crypt(fh.read()))

    while True:
        try:
            stream = c_defender.WIN32_STREAM_ID(buf)
        except EOFError:
            break
        data = buf.read(stream.Size)

        if stream.StreamId == STREAM_ID.DATA:
            yield (filename, data)
        elif stream.StreamId == STREAM_ID.EA_DATA:
            yield (f"{filename}.ea_data", data)
        elif stream.StreamId == STREAM_ID.SECURITY_DATA:
            yield (f"{filename}.security_descriptor", data)
        elif stream.StreamId == STREAM_ID.ALTERNATE_DATA:
            sanitized_stream_name = "".join(x for x in stream.StreamName if x.isalnum())
            yield (f"{filename}.{sanitized_stream_name}", data)
        elif stream.StreamId == STREAM_ID.LINK:
            yield (f"{filename}.link", data)
        elif stream.StreamId == STREAM_ID.PROPERTY_DATA:
            yield (f"{filename}.property_data", data)
        elif stream.StreamId == STREAM_ID.OBJECT_ID:
            yield (f"{filename}.object_id", data)
        elif stream.StreamId == STREAM_ID.REPARSE_DATA:
            yield (f"{filename}.reparse_data", data)
        elif stream.StreamId == STREAM_ID.SPARSE_BLOCK:
            yield (f"{filename}.sparse_block", data)
        elif stream.StreamId == STREAM_ID.TXFS_DATA:
            yield (f"{filename}.txfs_data", data)
        elif stream.StreamId == STREAM_ID.GHOSTED_FILE_EXTENTS:
            yield (f"{filename}.ghosted_file_extents", data)
        else:
            raise ValueError(f"Unexpected Stream ID {stream.StreamId}")


class QuarantineEntry:
    def __init__(self, fh: BinaryIO):
        # Decrypt & Parse the header so that we know the section sizes
        self.header = c_defender.QuarantineEntryFileHeader(rc4_crypt(fh.read(60)))

        # Decrypt & Parse Section 1. This will tell us some information about this quarantine entry.
        # These properties are shared for all quarantine entry resources associated with this quarantine entry.
        self.metadata = c_defender.QuarantineEntrySection1(rc4_crypt(fh.read(self.header.Section1Size)))

        self.timestamp = ts.wintimestamp(self.metadata.Timestamp)
        self.quarantine_id = self.metadata.Id
        self.scan_id = self.metadata.ScanId
        self.threat_id = self.metadata.ThreatId
        self.detection_name = self.metadata.DetectionName

        # The second section contains the number of quarantine entry resources contained in this quarantine entry,
        # as well as their offsets. After that, the individal quarantine entry resources start.
        resource_buf = BytesIO(rc4_crypt(fh.read(self.header.Section2Size)))
        resource_info = c_defender.QuarantineEntrySection2(resource_buf)

        # List holding all quarantine entry resources that belong to this quarantine entry.
        self.resources: list[QuarantineEntryResource] = []

        for offset in resource_info.EntryOffsets:
            resource_buf.seek(offset)
            self.resources.append(QuarantineEntryResource(resource_buf))


class QuarantineEntryResource:
    def __init__(self, fh: BinaryIO):
        self.metadata = c_defender.QuarantineEntryResource(fh)
        self.detection_path = self.metadata.DetectionPath
        self.field_count = self.metadata.FieldCount
        self.detection_type = self.metadata.DetectionType

        # It is possible that certain fields miss from a QuarantineEntryResource even though we expect them. Thus, we
        # initialize them in advance with a None value.
        self.resource_id = None
        self.creation_time = None
        self.last_access_time = None
        self.last_write_time = None

        self.unknown_fields = []

        # As the fields are aligned, we need to parse them individually
        offset = fh.tell()
        for _ in range(self.field_count):
            # Align
            offset = (offset + 3) & 0xFFFFFFFC
            fh.seek(offset)
            # Parse
            field = c_defender.QuarantineEntryResourceField(fh)
            self._add_field(field)

            # Move pointer
            offset += 4 + field.Size

    def _add_field(self, field: c_defender.QuarantineEntryResourceField) -> None:
        if field.Identifier == FIELD_IDENTIFIER.CQuaResDataID_File:
            self.resource_id = field.Data.hex().upper()
        elif field.Identifier == FIELD_IDENTIFIER.PhysicalPath:
            # Decoding as utf-16 leaves a trailing null-byte that we have to strip off.
            self.detection_path = field.Data.decode("utf-16").rstrip("\x00")
        elif field.Identifier == FIELD_IDENTIFIER.CreationTime:
            self.creation_time = ts.wintimestamp(int.from_bytes(field.Data, "little"))
        elif field.Identifier == FIELD_IDENTIFIER.LastAccessTime:
            self.last_access_time = ts.wintimestamp(int.from_bytes(field.Data, "little"))
        elif field.Identifier == FIELD_IDENTIFIER.LastWriteTime:
            self.last_write_time = ts.wintimestamp(int.from_bytes(field.Data, "little"))
        elif field.Identifier not in FIELD_IDENTIFIER:
            self.unknown_fields.append(field)
