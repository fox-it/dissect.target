from __future__ import annotations

import logging
import lzma
from typing import TYPE_CHECKING, Any, BinaryIO, Callable

import zstandard
from dissect.cstruct import cstruct
from dissect.util import ts
from dissect.util.compression import lz4

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

log = logging.getLogger(__name__)

# The events have undocumented fields that are not part of the record
JournalRecord = TargetRecordDescriptor(
    "linux/log/journal",
    [
        ("datetime", "ts"),
        # User Journal fields
        ("string", "message"),
        ("string", "message_id"),
        ("varint", "priority"),
        ("path", "code_file"),
        ("varint", "code_line"),
        ("string", "code_func"),
        ("varint", "errno"),
        ("string", "invocation_id"),
        ("string", "user_invocation_id"),
        ("string", "syslog_facility"),
        ("string", "syslog_identifier"),
        ("varint", "syslog_pid"),
        ("string", "syslog_raw"),
        ("string", "documentation"),
        ("varint", "tid"),
        ("string", "unit"),
        ("string", "user_unit"),
        # Trusted Journal fields
        ("varint", "pid"),
        ("varint", "uid"),
        ("varint", "gid"),
        ("string", "comm"),
        ("path", "exe"),
        ("string", "cmdline"),
        ("string", "cap_effective"),
        ("varint", "audit_session"),
        ("varint", "audit_loginuid"),
        ("path", "systemd_cgroup"),
        ("string", "systemd_slice"),
        ("string", "systemd_unit"),
        ("string", "systemd_user_unit"),
        ("string", "systemd_user_slice"),
        ("string", "systemd_session"),
        ("string", "systemd_owner_uid"),
        ("string", "selinux_context"),
        ("string", "boot_id"),
        ("string", "machine_id"),
        ("string", "systemd_invocation_id"),
        ("string", "transport"),
        ("string", "stream_id"),
        ("string", "line_break"),
        ("string", "namespace"),
        ("string", "runtime_scope"),
        # Kernel Journal fields
        ("string", "kernel_device"),
        ("string", "kernel_subsystem"),
        ("string", "udev_sysname"),
        ("path", "udev_devnode"),
        ("path", "udev_devlink"),
        # Other fields
        ("string", "journal_hostname"),
        ("path", "source"),
    ],
)

journal_def = """
#define HEADER_SIGNATURE b"LPKSHHRH"

typedef uint8 uint8_t;
typedef uint32 le32_t;
typedef uint64 le64_t;

enum State : uint8_t {
    OFFLINE   =  0,
    ONLINE    =  1,
    ARCHIVED  =  2,
    UNKNOWN
};

union sd_id128_t {
    uint8_t   bytes[16];
    uint64_t  qwords[2];
};

flag IncompatibleFlag : le32_t {
    HEADER_INCOMPATIBLE_COMPRESSED_XZ   = 1,
    HEADER_INCOMPATIBLE_COMPRESSED_LZ4  = 2,
    HEADER_INCOMPATIBLE_KEYED_HASH      = 4,
    HEADER_INCOMPATIBLE_COMPRESSED_ZSTD = 8,
    HEADER_INCOMPATIBLE_COMPACT         = 16,             // indicates that the Journal file uses the new binary format
};

struct Header {
    char              signature[8];
    le32_t            compatible_flags;
    IncompatibleFlag  incompatible_flags;
    State             state;
    uint8_t           reserved[7];
    sd_id128_t        file_id;
    sd_id128_t        machine_id;
    sd_id128_t        tail_entry_boot_id;
    sd_id128_t        seqnum_id;
    le64_t            header_size;
    le64_t            arena_size;
    le64_t            data_hash_table_offset;
    le64_t            data_hash_table_size;
    le64_t            field_hash_table_offset;
    le64_t            field_hash_table_size;
    le64_t            tail_object_offset;
    le64_t            n_objects;
    le64_t            n_entries;
    le64_t            tail_entry_seqnum;
    le64_t            head_entry_seqnum;
    le64_t            entry_array_offset;
    le64_t            head_entry_realtime;
    le64_t            tail_entry_realtime;
    le64_t            tail_entry_monotonic;
    le64_t            n_data;
    le64_t            n_fields;
    le64_t            n_tags;
    le64_t            n_entry_arrays;
    le64_t            data_hash_chain_depth;
    le64_t            field_hash_chain_depth;
    le32_t            tail_entry_array_offset;
    le32_t            tail_entry_array_n_entries;
    le64_t            tail_entry_offset;
};

enum ObjectType : uint8 {
    OBJECT_UNUSED,
    OBJECT_DATA,
    OBJECT_FIELD,
    OBJECT_ENTRY,
    OBJECT_DATA_HASH_TABLE,
    OBJECT_FIELD_HASH_TABLE,
    OBJECT_ENTRY_ARRAY,
    OBJECT_TAG,
    _OBJECT_TYPE_MAX
};

flag ObjectFlag : uint8 {
    OBJECT_UNCOMPRESSED      =  0,
    OBJECT_COMPRESSED_XZ     =  1,
    OBJECT_COMPRESSED_LZ4    =  2,
    OBJECT_COMPRESSED_ZSTD   =  4,
    _OBJECT_COMPRESSED_MASK  =  7
};

struct ObjectHeader {
    ObjectType  type;                                     // The type field is one of the object types listed above
    uint8_t     flags;                                    // If DATA object the value is ObjectFlag
    uint8_t     reserved[6];
    le64_t      size;                                     // The size field encodes the size of the object including all its headers and payload
};


// The first four members are copied from ObjectHeader, so that the size can be used as the length of payload
struct DataObject {
    // ObjectType  type;
    ObjectFlag  flags;
    uint8_t     reserved[6];
    le64_t      size;
    le64_t      hash;
    le64_t      next_hash_offset;
    le64_t      next_field_offset;
    le64_t      entry_offset;
    le64_t      entry_array_offset;
    le64_t      n_entries;
    char        payload[size - 64];                       // Data objects carry actual field data in the payload[] array.
};

// If the HEADER_INCOMPATIBLE_COMPACT flag is set, two extra fields are stored to allow immediate access
// to the tail entry array in the DATA object's entry array chain.
struct DataObject_Compact {
    // ObjectType  type;
    ObjectFlag  flags;
    uint8_t     reserved[6];
    le64_t      size;
    le64_t      hash;
    le64_t      next_hash_offset;
    le64_t      next_field_offset;
    le64_t      entry_offset;
    le64_t      entry_array_offset;
    le64_t      n_entries;
    le32_t      tail_entry_array_offset;
    le32_t      tail_entry_array_n_entries;
    char        payload[size - 72];                       // Data objects carry actual field data in the payload[] array.
};

struct EntryItem {
    le64_t object_offset;
    le64_t hash;
};

struct EntryItem_Compact {
    le32_t object_offset;
}

// The first four members are copied from ObjectHeader, so that the size can be used as the length of items
struct EntryObject {
    ObjectType  type;
    uint8_t     flags;
    uint8_t     reserved[6];
    le64_t      size;
    le64_t      seqnum;
    le64_t      realtime;
    le64_t      monotonic;
    sd_id128_t  boot_id;
    le64_t      xor_hash;
    EntryItem   items[(size - 64) / 16];                  // The size minus the previous members divided by the size of the items
};

// If the HEADER_INCOMPATIBLE_COMPACT flag is set, DATA object offsets are stored as 32-bit integers instead of 64bit
// and the unused hash field per data object is not stored anymore.
struct EntryObject_Compact {
    ObjectType  type;
    uint8_t     flags;
    uint8_t     reserved[6];
    le64_t      size;
    le64_t      seqnum;
    le64_t      realtime;
    le64_t      monotonic;
    sd_id128_t  boot_id;
    le64_t      xor_hash;
    EntryItem_Compact   items[(size - 64) / 4];
};

// The first four members are copied from from ObjectHeader, so that the size can be used as the length of entry_object_offsets
struct EntryArrayObject {
    // ObjectType  type;
    uint8_t     flags;
    uint8_t     reserved[6];
    le64_t      size;
    le64_t      next_entry_array_offset;
    le64_t      entry_object_offsets[(size - 24) / 8];    // The size minus the previous members divided by the size of the offset
};

struct EntryArrayObject_Compact {
    // ObjectType  type;
    uint8_t     flags;
    uint8_t     reserved[6];
    le64_t      size;
    le64_t      next_entry_array_offset;
    le32_t      entry_object_offsets[(size - 24) / 4];
};
"""  # noqa: E501

c_journal = cstruct().load(journal_def)


def get_optional(value: str, to_type: Callable) -> Any | None:
    """Return the value if True, otherwise return None."""

    if not value:
        return None

    try:
        return to_type(value)

    except ValueError as e:
        log.error("Unable to cast '%s' to %s", value, to_type)  # noqa: TRY400
        log.debug("", exc_info=e)
        return None


# Sometimes stringy None is inserted by external tools like Ansible
def int_or_none(value: str) -> int | None:
    return int(value) if value and value != "None" else None


class JournalFile:
    """Parse Systemd Journal file format.

    References:
        - https://github.com/systemd/systemd/blob/206f0f397edf1144c63a158fb30f496c3e89f256/docs/JOURNAL_FILE_FORMAT.md
        - https://github.com/libyal/dtformats/blob/c4fc2b8102702c64b58f145971821986bf74e6c0/documentation/Systemd%20journal%20file%20format.asciidoc
    """

    def __init__(self, fh: BinaryIO, target: Target):
        self.fh = fh
        self.target = target

        try:
            self.header = c_journal.Header(self.fh)
        except EOFError as e:
            raise ValueError(f"Invalid systemd Journal file: {e}")

        if self.header.signature != c_journal.HEADER_SIGNATURE:
            raise ValueError(f"Journal file has invalid magic header: {self.header.signature!r}'")

    def decode_value(self, value: bytes) -> tuple[str, str]:
        """Decode the given bytes to a key value pair."""
        value = value.decode(errors="surrogateescape").strip().lstrip("_")
        key, value = value.split("=", 1)
        key = key.lower()
        return key, value

    def __iter__(self) -> Iterator[dict[str, int | str]]:
        "Iterate over the entry objects to read payloads."

        offset = self.header.entry_array_offset
        while offset != 0:
            self.fh.seek(offset)
            object_type = self.fh.read(1)[0]

            if object_type == c_journal.ObjectType.OBJECT_UNUSED:
                self.target.log.warning(
                    "ObjectType OBJECT_UNUSED encountered for next OBJECT_ENTRY_ARRAY offset at 0x%X. "
                    "This indicates allocated space in the journal file which is not used yet.",
                    offset,
                )
                break

            elif object_type != c_journal.ObjectType.OBJECT_ENTRY_ARRAY:
                raise ValueError(f"Expected OBJECT_ENTRY_ARRAY or OBJECT_UNUSED at offset {offset}")

            if self.header.incompatible_flags & c_journal.IncompatibleFlag.HEADER_INCOMPATIBLE_COMPACT:
                entry_array_object = c_journal.EntryArrayObject_Compact(self.fh)
            else:
                entry_array_object = c_journal.EntryArrayObject(self.fh)

            for entry_object_offset in entry_array_object.entry_object_offsets:
                if entry_object_offset:
                    yield from self._parse_entry_object(offset=entry_object_offset)

            offset = entry_array_object.next_entry_array_offset

    def _parse_entry_object(self, offset: int) -> Iterator[dict]:
        self.fh.seek(offset)

        try:
            if self.header.incompatible_flags & c_journal.IncompatibleFlag.HEADER_INCOMPATIBLE_COMPACT:
                entry = c_journal.EntryObject_Compact(self.fh)
            else:
                entry = c_journal.EntryObject(self.fh)

        except EOFError as e:
            self.target.log.warning("Unable to read Journal EntryObject at offset %s in: %s", offset, self.fh)
            self.target.log.debug("", exc_info=e)
            return

        event = {"ts": ts.from_unix_us(entry.realtime)}
        for item in entry.items:
            try:
                self.fh.seek(item.object_offset)

                if self.fh.read(1)[0] != c_journal.ObjectType.OBJECT_DATA:
                    continue

                if self.header.incompatible_flags & c_journal.IncompatibleFlag.HEADER_INCOMPATIBLE_COMPACT:
                    data_object = c_journal.DataObject_Compact(self.fh)
                else:
                    data_object = c_journal.DataObject(self.fh)

                if not data_object.payload:
                    continue

                data = data_object.payload

                if data_object.flags & c_journal.ObjectFlag.OBJECT_COMPRESSED_XZ:
                    data = lzma.decompress(data)

                elif data_object.flags & c_journal.ObjectFlag.OBJECT_COMPRESSED_LZ4:
                    data = lz4.decompress(data[8:])

                elif data_object.flags & c_journal.ObjectFlag.OBJECT_COMPRESSED_ZSTD:
                    data = zstandard.decompress(data)

                key, value = self.decode_value(data)
                event[key] = value

            except Exception as e:
                self.target.log.warning(
                    "Journal DataObject could not be parsed at offset %s in %s",
                    item.object_offset,
                    getattr(self.fh, "name", None),
                )
                self.target.log.debug("", exc_info=e)
                continue

        yield event


class JournalPlugin(Plugin):
    """Systemd Journal plugin."""

    JOURNAL_PATHS = ("/var/log/journal",)  # TODO: /run/systemd/journal
    JOURNAL_GLOB = "*/*.journal*"  # The extensions .journal and .journal~

    def __init__(self, target: Target):
        super().__init__(target)
        self.journal_files = []

        for journal_path in self.JOURNAL_PATHS:
            self.journal_files.extend(self.target.fs.path(journal_path).glob(self.JOURNAL_GLOB))

    def check_compatible(self) -> None:
        if not self.journal_files:
            raise UnsupportedPluginError("No journald files found")

    @export(record=JournalRecord)
    def journal(self) -> Iterator[JournalRecord]:
        """Return the contents of Systemd Journal log files.

        References:
            - https://wiki.archlinux.org/title/Systemd/Journal
            - https://github.com/systemd/systemd/blob/9203abf79f1d05fdef9b039e7addf9fc5a27752d/man/systemd.journal-fields.xml
        """
        path_function = self.target.fs.path

        for journal_file in self.journal_files:
            if not journal_file.is_file():
                self.target.log.warning("Unable to parse journal file as it is not a file: %s", journal_file)
                continue

            try:
                fh = journal_file.open()
                journal = JournalFile(fh, self.target)

            except Exception as e:
                self.target.log.warning("Unable to parse journal file structure: %s: %s", journal_file, str(e))
                self.target.log.debug("", exc_info=e)
                continue

            for entry in journal:
                yield JournalRecord(
                    ts=entry.get("ts"),
                    message=entry.get("message"),
                    message_id=entry.get("message_id"),
                    priority=int_or_none(entry.get("priority")),
                    code_file=get_optional(entry.get("code_file"), path_function),
                    code_line=int_or_none(entry.get("code_line")),
                    code_func=entry.get("code_func"),
                    errno=int_or_none(entry.get("errno")),
                    invocation_id=entry.get("invocation_id"),
                    user_invocation_id=entry.get("user_invocation_id"),
                    syslog_facility=entry.get("syslog_facility"),
                    syslog_identifier=entry.get("syslog_identifier"),
                    syslog_pid=int_or_none(entry.get("syslog_pid")),
                    syslog_raw=entry.get("syslog_raw"),
                    documentation=entry.get("documentation"),
                    tid=int_or_none(entry.get("tid")),
                    unit=entry.get("unit"),
                    user_unit=entry.get("user_unit"),
                    pid=int_or_none(entry.get("pid")),
                    uid=int_or_none(entry.get("uid")),
                    gid=int_or_none(entry.get("gid")),
                    comm=entry.get("comm"),
                    exe=get_optional(entry.get("exe"), path_function),
                    cmdline=entry.get("cmdline"),
                    cap_effective=entry.get("cap_effective"),
                    audit_session=int_or_none(entry.get("audit_session")),
                    audit_loginuid=int_or_none(entry.get("audit_loginuid")),
                    systemd_cgroup=get_optional(entry.get("systemd_cgroup"), path_function),
                    systemd_slice=entry.get("systemd_slice"),
                    systemd_unit=entry.get("systemd_unit"),
                    systemd_user_unit=entry.get("systemd_user_unit"),
                    systemd_user_slice=entry.get("systemd_user_slice"),
                    systemd_session=entry.get("systemd_session"),
                    systemd_owner_uid=entry.get("systemd_owner_uid"),
                    selinux_context=entry.get("selinux_context"),
                    boot_id=entry.get("boot_id"),
                    machine_id=entry.get("machine_id"),
                    systemd_invocation_id=entry.get("systemd_invocation_id"),
                    transport=entry.get("transport"),
                    stream_id=entry.get("stream_id"),
                    line_break=entry.get("line_break"),
                    namespace=entry.get("namespace"),
                    runtime_scope=entry.get("runtime_scope"),
                    kernel_device=entry.get("kernel_device"),
                    kernel_subsystem=entry.get("kernel_subsystem"),
                    udev_sysname=entry.get("udev_sysname"),
                    udev_devnode=get_optional(entry.get("udev_devnode"), path_function),
                    udev_devlink=get_optional(entry.get("udev_devlink"), path_function),
                    journal_hostname=entry.get("hostname"),
                    source=journal_file,
                    _target=self.target,
                )
