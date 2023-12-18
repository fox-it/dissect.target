from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, BinaryIO, Generator, Iterable, Iterator, Union

import dissect.util.ts as ts
from dissect.cstruct import Structure, cstruct
from flow.record import Record

from dissect.target import plugin
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor

DEFENDER_EVTX_FIELDS = [
    ("uint32", "EventID"),
    ("string", "Provider_Name"),
    ("string", "Action_ID"),
    ("string", "Action_Name"),
    ("string", "Additional_Actions_ID"),
    ("string", "Additional_Actions_String"),
    ("string", "Category_ID"),
    ("string", "Category_Name"),
    ("string", "Channel"),
    ("string", "Computer"),
    ("string", "Correlation_ActivityID"),
    ("string", "Correlation_RelatedActivityID"),
    ("string", "Detection_ID"),
    ("datetime", "Detection_Time"),
    ("string", "Detection_User"),
    ("string", "Engine_Version"),
    ("string", "Error_Code"),
    ("string", "Error_Description"),
    ("string", "EventID_Qualifiers"),
    ("string", "EventRecordID"),
    ("string", "Execution_ID"),
    ("string", "Execution_Name"),
    ("string", "Execution_ProcessID"),
    ("string", "Execution_ThreadID"),
    ("string", "FWLink"),
    ("string", "Keywords"),
    ("string", "Level"),
    ("string", "Opcode"),
    ("string", "Origin_ID"),
    ("string", "Origin_Name"),
    ("string", "Path"),
    ("string", "Post_Clean_Status"),
    ("string", "Pre_Execution_Status"),
    ("string", "Process_Name"),
    ("string", "Product_Name"),
    ("string", "Product_Version"),
    ("string", "Provider_Guid"),
    ("string", "Remediation_User"),
    ("string", "Security_intelligence_Version"),
    ("string", "Security_UserID"),
    ("string", "Severity_ID"),
    ("string", "Severity_Name"),
    ("string", "Source_ID"),
    ("string", "Source_Name"),
    ("string", "State"),
    ("string", "Status_Code"),
    ("string", "Status_Description"),
    ("string", "Task"),
    ("string", "Threat_ID"),
    ("string", "Threat_Name"),
    ("string", "Type_ID"),
    ("string", "Type_Name"),
    ("string", "Version"),
]

DEFENDER_LOG_DIR = "sysvol/windows/system32/winevt/logs"
DEFENDER_LOG_FILENAME_GLOB = "Microsoft-Windows-Windows Defender*"
EVTX_PROVIDER_NAME = "Microsoft-Windows-Windows Defender"

DEFENDER_QUARANTINE_DIR = "sysvol/programdata/microsoft/windows defender/quarantine"
DEFENDER_KNOWN_DETECTION_TYPES = [b"internalbehavior", b"regkey", b"runkey"]

DEFENDER_EXCLUSION_KEY = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions"

DefenderLogRecord = TargetRecordDescriptor(
    "filesystem/windows/defender/evtx",
    [("datetime", "ts")] + DEFENDER_EVTX_FIELDS,
)

DefenderExclusionRecord = TargetRecordDescriptor(
    "filesystem/windows/defender/exclusion",
    [
        ("datetime", "regf_mtime"),
        ("string", "type"),
        ("string", "value"),
    ],
)

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

c_defender = cstruct()
c_defender.load(defender_def)

STREAM_ID = c_defender.STREAM_ID
STREAM_ATTRIBUTES = c_defender.STREAM_ATTRIBUTES
FIELD_IDENTIFIER = c_defender.FIELD_IDENTIFIER


def parse_iso_datetime(datetime_value: str) -> datetime:
    """Parse ISO8601 serialized datetime with `Z` ending."""
    return datetime.strptime(datetime_value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def filter_records(records: Iterable, field_name: str, field_value: Any) -> Iterator[DefenderLogRecord]:
    """
    Apply a filter on an Iterable of records, returning only records that have the given field value for the given
    field name.
    """

    def filter_func(record: Record) -> bool:
        return hasattr(record, field_name) and getattr(record, field_name) == field_value

    return filter(filter_func, records)


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
        if stream.StreamId == STREAM_ID.SECURITY_DATA:
            yield (f"{filename}.security_descriptor", data)
        elif stream.StreamId == STREAM_ID.DATA:
            yield (filename, data)
        elif stream.StreamId == STREAM_ID.ALTERNATE_DATA:
            sanitized_stream_name = "".join(x for x in stream.StreamName if x.isalnum())
            yield (f"{filename}.{sanitized_stream_name}", data)
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
        self.resources = []

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

    def _add_field(self, field: Structure):
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
        elif field.Identifier not in FIELD_IDENTIFIER.values.values():
            self.unknown_fields.append(field)


class MicrosoftDefenderPlugin(plugin.Plugin):
    """Plugin that parses artifacts created by Microsoft Defender.

    This includes the EVTX logs, as well as recovery of artefacts from the quarantine folder.
    """

    __namespace__ = "defender"

    def check_compatible(self) -> None:
        # Either the Defender log folder, the quarantine folder or the exclusions registry key
        # has to exist for this plugin to be compatible.

        if not any(
            [
                self.target.fs.path(DEFENDER_LOG_DIR).exists(),
                self.target.fs.path(DEFENDER_QUARANTINE_DIR).exists(),
                (
                    self.target.has_function("registry")
                    and len(list(self.target.registry.keys(DEFENDER_EXCLUSION_KEY))) > 0
                ),
            ]
        ):
            raise UnsupportedPluginError("No Defender objects found")

    @plugin.export(record=DefenderLogRecord)
    def evtx(self) -> Generator[Record, None, None]:
        """Parse Microsoft Defender evtx log files"""

        defender_evtx_field_names = [field_name for _, field_name in DEFENDER_EVTX_FIELDS]

        evtx_records = self.target.evtx(logs_dir=DEFENDER_LOG_DIR, log_file_glob=DEFENDER_LOG_FILENAME_GLOB)
        defender_evtx_records = filter_records(evtx_records, "Provider_Name", "Microsoft-Windows-Windows Defender")

        for evtx_record in defender_evtx_records:
            record_fields = {}
            for field_name in defender_evtx_field_names:
                if not hasattr(evtx_record, field_name):
                    continue

                value = getattr(evtx_record, field_name)

                if field_name == "Detection_Time" and value:
                    value = parse_iso_datetime(value)

                record_fields[field_name] = value

            yield DefenderLogRecord(**record_fields, _target=self.target)

    @plugin.export(record=[DefenderQuarantineRecord, DefenderFileQuarantineRecord])
    def quarantine(self) -> Iterator[Union[DefenderQuarantineRecord, DefenderFileQuarantineRecord]]:
        """Parse the quarantine folder of Microsoft Defender for quarantine entry resources.

        Quarantine entry resources contain metadata about detected threats that Microsoft Defender has placed in
        quarantine.
        """
        for entry in self.get_quarantine_entries():
            # These fields are present for all (currently known) quarantine entry types
            fields = {
                "ts": entry.timestamp,
                "quarantine_id": entry.quarantine_id,
                "scan_id": entry.scan_id,
                "threat_id": entry.threat_id,
                "detection_name": entry.detection_name,
            }
            for resource in entry.resources:
                fields.update({"detection_type": resource.detection_type})
                if resource.detection_type == b"file":
                    # These fields are only available for file based detections
                    fields.update(
                        {
                            "detection_path": resource.detection_path,
                            "creation_time": resource.creation_time,
                            "last_write_time": resource.last_write_time,
                            "last_accessed_time": resource.last_access_time,
                            "resource_id": resource.resource_id,
                        }
                    )
                    yield DefenderFileQuarantineRecord(**fields, _target=self.target)
                else:
                    # For these types, we know that they have no known additional data to add to the Quarantine Record.
                    if resource.detection_type not in DEFENDER_KNOWN_DETECTION_TYPES:
                        self.target.log.warning(
                            "Unknown Defender Detection Type %s, yielding a generic quarantine record.",
                            resource.detection_type,
                        )
                    # For anything other than a file, we yield a generic DefenderQuarantineRecord.
                    yield DefenderQuarantineRecord(**fields, _target=self.target)

    @plugin.export(record=DefenderExclusionRecord)
    def exclusions(self) -> Iterator[DefenderExclusionRecord]:
        """Yield Microsoft Defender exclusions from the Registry."""

        # Iterate through all possible versions of the key for Defender exclusions
        for exclusions_registry_key in self.target.registry.keys(DEFENDER_EXCLUSION_KEY):
            # Every subkey of the exclusions key is a 'type' of exclusion, e.g. 'path' 'process' or 'extension'.
            for exclusion_type_subkey in exclusions_registry_key.subkeys():
                # Every value is an exclusion for a said type. The 'name' property of said registry value holds
                # what is being excluded from Defender (e.g. powershell.exe, notepad.txt)
                for exclusion in exclusion_type_subkey.values():
                    exclusion_value = exclusion.name
                    exclusion_type = exclusion_type_subkey.name
                    # Due to the fact that every exclusion is a registry value and not a registry key, we can only know
                    # the last modified timestamp of the exclusion type for a given exclusion, not a timestamp for the
                    # exclusion itself. We reflect this to the analyst by using the regf_mtime field.
                    yield DefenderExclusionRecord(
                        regf_mtime=exclusion_type_subkey.timestamp,
                        type=exclusion_type,
                        value=exclusion_value,
                    )

    @plugin.arg(
        "--output",
        "-o",
        dest="output_dir",
        type=Path,
        required=True,
        help="Path to recover quarantined file to.",
    )
    @plugin.export(output="none")
    def recover(self, output_dir: Path) -> None:
        """Recover files that have been placed into quarantine by Microsoft Defender.

        Microsoft Defender RC4 encrypts the output of the 'BackupRead' function when it places a file into quarantine.
        This means multiple data streams can be contained in a single quarantined file, including zone identifier
        information.
        """
        if not output_dir.exists():
            raise ValueError("Output directory does not exist.")
        quarantine_directory = self.target.fs.path(DEFENDER_QUARANTINE_DIR)
        resourcedata_directory = quarantine_directory.joinpath("ResourceData")
        if resourcedata_directory.exists() and resourcedata_directory.is_dir():
            recovered_files = []
            for entry in self.get_quarantine_entries():
                for resource in entry.resources:
                    if resource.detection_type != b"file":
                        # We can only recover file entries
                        continue
                    # First two characters of the resource ID is the subdirectory that will contain the quarantined file
                    subdir = resource.resource_id[0:2]
                    resourcedata_location = resourcedata_directory.joinpath(subdir).joinpath(resource.resource_id)
                    if not resourcedata_location.exists():
                        self.target.log.warning(f"Could not find a ResourceData file for {entry.resource_id}.")
                        continue
                    if not resourcedata_location.is_file():
                        self.target.log.warning(f"{resourcedata_location} is not a file!")
                        continue
                    if resourcedata_location in recovered_files:
                        # We already recovered this file
                        continue
                    with resourcedata_location.open() as fh:
                        # We restore the file with the resource_id as its filename. While we could 'guess' the filename
                        # based on the information we have from the associated quarantine entry, there is a potential
                        # that different files have the same filename. Analysts can use the quarantine records to cross
                        # reference.
                        for dest_filename, dest_buf in recover_quarantined_file_streams(fh, resource.resource_id):
                            output_filename = output_dir.joinpath(dest_filename)
                            self.target.log.info(f"Saving {output_filename}")
                            output_filename.write_bytes(dest_buf)

                    # Make sure we do not recover the same file multiple times if it has multiple entries
                    recovered_files.append(resourcedata_location)

    def get_quarantine_entries(self) -> Iterator[QuarantineEntry]:
        """Yield Windows Defender quarantine entries."""
        quarantine_directory = self.target.fs.path(DEFENDER_QUARANTINE_DIR)
        entries_directory = quarantine_directory.joinpath("entries")

        if not entries_directory.is_dir():
            return
        for guid_path in entries_directory.iterdir():
            if not guid_path.exists() or not guid_path.is_file():
                continue
            with guid_path.open() as entry_fh:
                entry = QuarantineEntry(entry_fh)

            # Warn on discovery of fields that we do not have knowledge of what they are / do.
            for resource in entry.resources:
                for unknown_field in resource.unknown_fields:
                    self.target.log.warning(f"Encountered an unknown field identifier: {unknown_field.Identifier}")
            yield entry
