from __future__ import annotations

import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from dissect.cstruct import cstruct
from dissect.sql import sqlite3
from dissect.util.ts import wintimestamp
from flow.record import GroupedRecord

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import WindowsUserRecord, create_extended_descriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

appdb_def = """
typedef struct {
    char     Magic[4];                 // Always b"DNPW"
    DWORD    Version;                  // Versions 1 (win8) and 3 (win10) seem to exist
    QWORD    Timestamp;                // According to some sources this is LastNotificationDate,
                                       // but that seems incorrect.
    DWORD    NextNotificationId;
    DWORD    Unknown;
    char     Padding[8];
} ChunkHeader;                         // size: 0x20

typedef struct {
    WORD     InUse;                    // ??
    WORD     NextTileWriteIndex;       // ??
    WORD     NextToastWriteIndex;      // ??
    BYTE     Flags[2];
} ChunkInfo;

typedef struct {
    QWORD    Timestamp1;               // ??
    QWORD    Timestamp2;               // Is this time to refresh?
    char     Uri[1024];                // Is this the correct size?
    char     Padding[0x818 - 0x410];
} PushDescriptor;                      // size: 0x818

typedef struct {
    DWORD    Id;
    DWORD    Zero;                     // ??
    QWORD    Timestamp;                // ??
    WORD     Unknown;
    WORD     DataLength;
    char     Data[DataLength];
    char     Padding[0x118 - 0x14 - DataLength];
} BadgeContent;                        // size: 0x118

typedef struct {
    DWORD    UniqueId;                 // ??
    DWORD    Zero;
    QWORD    ExpiryTime;               // The time this tile expires
    QWORD    ArrivalTime;              // The time this tile was set
    BYTE     Type;                     // ??
    BYTE     Index;
    WORD     ContentLength;
    wchar_t  Name[18];
} TileDescriptor;                      // size: 0x40

typedef struct {
    DWORD    UniqueId;                 // ??
    DWORD    Zero;
    QWORD    ExpiryTime;               // The time this toast expires
    QWORD    ArrivalTime;              // The time this toast was set
    BYTE     Type;                     // ??
    BYTE     Index;
    WORD     ContentLength;
    wchar_t  Name1[17];
    wchar_t  Name2[17];
} ToastDescriptor;                     // size: 0x60

typedef struct {
  char Content[0x1400];
} DataXML;                             // size: 0x1400

typedef struct {
    ChunkHeader     Header;            // Only populated for first chunk, else zeroed
    ChunkInfo       Info;
    PushDescriptor  Push;
    BadgeContent    Badge;
    TileDescriptor  Tiles[5];          // start @ 0x958
    DataXML         TileXml[5];

    // For the in use chunks, 0x14 ToastDiscriptors have an Index, but there
    // is space for more. Maybe this is used in case of deleted entries?
    ToastDescriptor Toasts[0x14];      // start @ 0x6e98
    char            Padding1[0x1e00];  // start @ 0x7618
    DataXML         ToastXml[0x14];    // start @ 0x9418
    char            Padding2[0x13f8];  // start @ 0x22418
} Chunk;                               // size: 0x23810
"""

c_appdb = cstruct(endian="<").load(appdb_def)

APPDB_MAGIC = b"DNPW"
NUM_APPDB_CHUNKS = 256

AppDBRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/notification/appdb",
    [
        ("datetime", "timestamp"),
        ("varint", "version"),
        ("varint", "next_notification_id"),
    ],
)

AppDBPushRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/notification/appdb/push",
    [
        ("datetime", "push_ts1"),
        ("datetime", "push_ts2"),
        ("varint", "chunk_num"),
        ("uri", "push_uri"),
    ],
)

AppDBBadgeRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/notification/appdb/badge",
    [
        ("datetime", "badge_ts"),
        ("varint", "badge_id"),
        ("varint", "chunk_num"),
        ("string", "badge_data"),
    ],
)

AppDBTileRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/notification/appdb/tile",
    [
        ("datetime", "arrival_time"),
        ("datetime", "expiry_time"),
        ("varint", "id"),
        ("varint", "chunk_num"),
        ("varint", "type"),
        ("varint", "index"),
        ("string", "name"),
        ("string", "content"),
    ],
)

AppDBToastRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/notification/appdb/toast",
    [
        ("datetime", "arrival_time"),
        ("datetime", "expiry_time"),
        ("varint", "id"),
        ("varint", "chunk_num"),
        ("varint", "type"),
        ("varint", "index"),
        ("string", "name1"),
        ("string", "name2"),
        ("string", "content"),
    ],
)

WpnDatabaseNotificationRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/notification/wpndatabase",
    [
        ("datetime", "arrival_time"),
        ("datetime", "expiry_time"),
        ("varint", "order"),
        ("varint", "id"),
        ("varint", "handler_id"),
        ("string", "activity_id"),
        ("string", "type"),
        ("bytes", "payload"),
        ("string", "payload_type"),
        ("string", "tag"),
        ("string", "group"),
        ("varint", "boot_id"),
        ("boolean", "expires_on_reboot"),
    ],
)

WpnDatabaseNotificationHandlerRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/notification/wpndatabase/handler",
    [
        ("datetime", "created_time"),
        ("datetime", "modified_time"),
        ("varint", "id"),
        ("string", "primary_id"),
        ("string", "wns_id"),
        ("string", "handler_type"),
        ("varint", "wnf_event_name"),
        ("bytes", "system_data_property_set"),
    ],
)

NOTIFICATIONS_DIR = "AppData/Local/Microsoft/Windows/Notifications"


class NotificationsPlugin(Plugin):
    """Plugin that parses the notification databases on Windows 10 machines."""

    __namespace__ = "notifications"

    def __init__(self, target: Target):
        super().__init__(target)
        self.wpndb_files = []
        self.appdb_files = []

        for user_details in target.user_details.all_with_home():
            notification_dir = user_details.home_path.joinpath(NOTIFICATIONS_DIR)
            wpndb_file = notification_dir.joinpath("wpndatabase.db")
            appdb_file = notification_dir.joinpath("appdb.dat")

            if wpndb_file.exists():
                self.wpndb_files.append((user_details.user, wpndb_file))

            if appdb_file.exists():
                with appdb_file.open(mode="rb") as fp:
                    chunk = c_appdb.Chunk(fp)
                    if chunk.Header.Magic == APPDB_MAGIC:
                        version = chunk.Header.Version
                        if version == 3:
                            self.appdb_files.append((user_details.user, appdb_file))
                        else:
                            self.target.log.warning(
                                "Skipping %s: unsupported version %s.",
                                appdb_file,
                                version,
                            )
                            if version != 1:
                                self.target.log.warning(
                                    "Unknown appdb version %s in file %s, please consider providing us with a sample.",
                                    version,
                                    appdb_file,
                                )

    def check_compatible(self) -> None:
        if not self.wpndb_files and not self.appdb_files:
            raise UnsupportedPluginError("No or incompatible wpndatabase.db or appdb.dat files found")

    def _get_appdb_chunk_record(
        self,
        chunk: c_appdb.Chunk,
        user: WindowsUserRecord,
    ) -> AppDBRecord:
        chunk_timestamp = None
        if ts := chunk.Header.Timestamp:
            chunk_timestamp = wintimestamp(ts)

        return AppDBRecord(
            timestamp=chunk_timestamp,
            version=chunk.Header.Version,
            next_notification_id=chunk.Header.NextNotificationId,
        )

    def _get_appdb_push_record(
        self,
        chunk: c_appdb.Chunk,
        chunk_num: int,
        user: WindowsUserRecord,
    ) -> AppDBPushRecord | None:
        badge_record = None
        push_uri = chunk.Push.Uri.split(b"\x00")[0]
        push_uri = push_uri.decode("utf-8", errors="surrogateescape")

        if push_uri:
            push_timestamp1 = None
            if ts := chunk.Push.Timestamp1:
                push_timestamp1 = wintimestamp(ts)
            push_timestamp2 = None
            if ts := chunk.Push.Timestamp2:
                push_timestamp2 = wintimestamp(ts)

            badge_record = AppDBPushRecord(
                push_ts1=push_timestamp1,
                push_ts2=push_timestamp2,
                chunk_num=chunk_num,
                push_uri=push_uri,
                _target=self.target,
                _user=user,
            )

        return badge_record

    def _get_appdb_badge_record(
        self,
        chunk: c_appdb.Chunk,
        chunk_num: int,
        user: WindowsUserRecord,
    ) -> AppDBBadgeRecord | None:
        badge_record = None
        badge_id = chunk.Badge.Id

        if badge_id:
            badge_ts = None
            if ts := chunk.Badge.Timestamp:
                badge_ts = wintimestamp(ts)
            badge_data = chunk.Badge.Data.decode("utf-8", errors="surrogateescape")

            badge_record = AppDBBadgeRecord(
                badge_id=badge_id,
                badge_ts=badge_ts,
                chunk_num=chunk_num,
                badge_data=badge_data,
                _target=self.target,
                _user=user,
            )

        return badge_record

    def _get_appdb_tile_records(
        self,
        chunk: c_appdb.Chunk,
        chunk_num: int,
        user: WindowsUserRecord,
    ) -> list[AppDBTileRecord]:
        tile_records = []
        num_tiles = len(chunk.Tiles)

        for tile_no in range(num_tiles):
            tile = chunk.Tiles[tile_no]

            if tile.UniqueId:
                tile_arrival_time = None
                if ts := tile.ArrivalTime:
                    tile_arrival_time = wintimestamp(ts)
                tile_expiry_time = None
                if ts := tile.ExpiryTime:
                    tile_expiry_time = wintimestamp(ts)
                name = tile.Name.strip("\x00")

                xml_size = tile.ContentLength
                tile_xml = chunk.TileXml[tile_no].Content[:xml_size]
                tile_xml = tile_xml.decode("utf-8", errors="surrogateescape")

                tile_record = AppDBTileRecord(
                    arrival_time=tile_arrival_time,
                    expiry_time=tile_expiry_time,
                    id=tile.UniqueId,
                    chunk_num=chunk_num,
                    type=tile.Type,
                    index=tile.Index,
                    name=name,
                    content=tile_xml,
                    _target=self.target,
                    _user=user,
                )

                tile_records.append(tile_record)
        return tile_records

    def _get_appdb_toast_records(
        self,
        chunk: c_appdb.Chunk,
        chunk_num: int,
        user: WindowsUserRecord,
    ) -> list[AppDBToastRecord]:
        toast_records = []
        num_toasts = len(chunk.Toasts)

        for toast_no in range(num_toasts):
            toast = chunk.Toasts[toast_no]

            if toast.UniqueId:
                toast_arrival_time = None
                if ts := toast.ArrivalTime:
                    toast_arrival_time = wintimestamp(ts)
                toast_expiry_time = None
                if ts := toast.ExpiryTime:
                    toast_expiry_time = wintimestamp(ts)
                name1 = toast.Name1.strip("\x00")
                name2 = toast.Name2.strip("\x00")

                xml_size = toast.ContentLength
                toast_xml = chunk.ToastXml[toast_no].Content[:xml_size]
                toast_xml = toast_xml.decode("utf-8", errors="surrogateescape")

                toast_record = AppDBToastRecord(
                    arrival_time=toast_arrival_time,
                    expiry_time=toast_expiry_time,
                    id=toast.UniqueId,
                    chunk_num=chunk_num,
                    type=toast.Type,
                    index=toast.Index,
                    name1=name1,
                    name2=name2,
                    content=toast_xml,
                    _target=self.target,
                    _user=user,
                )

                toast_records.append(toast_record)
        return toast_records

    @export(record=[AppDBRecord, AppDBPushRecord, AppDBBadgeRecord, AppDBTileRecord, AppDBToastRecord])
    def appdb(self) -> Iterator[GroupedRecord]:
        """Retrun the data from Windows appdb.dat file.

        This file contains data presentted to the user, pushed by external
        sources. The appdb.dat file was used from Windows 8 to Windows 10 pre
        anniversary version. This plugin only supports appdb.dat version 3 from
        Windows 10.

        References:
            - http://www.swiftforensics.com/2016/06/prasing-windows-10-notification-database.html
        """
        for user, appdb_file in self.appdb_files:
            with appdb_file.open(mode="rb") as fp:
                for chunk_num in range(NUM_APPDB_CHUNKS):
                    chunk = c_appdb.Chunk(fp)

                    if chunk.Info.InUse == 0:
                        continue
                    elif chunk.Info.InUse != 1:
                        self.target.log.warning(
                            "Unknown field value %s for chunk.Info.InUse, please consider providing us with a sample.",
                            chunk.Info.InUse,
                        )
                        continue

                    if chunk_num == 0:
                        yield self._get_appdb_chunk_record(chunk, user)

                    push_record = self._get_appdb_push_record(chunk, chunk_num, user)
                    if push_record:
                        yield push_record

                    badge_record = self._get_appdb_badge_record(chunk, chunk_num, user)
                    if badge_record:
                        yield badge_record

                    yield from self._get_appdb_tile_records(chunk, chunk_num, user)

                    yield from self._get_appdb_toast_records(chunk, chunk_num, user)

    @export(record=[WpnDatabaseNotificationRecord, WpnDatabaseNotificationHandlerRecord])
    def wpndatabase(self) -> Iterator[WpnDatabaseNotificationRecord | WpnDatabaseNotificationHandlerRecord]:
        """Returns Windows Notifications from wpndatabase.db (post Windows 10 Anniversary).

        References:
            - https://inc0x0.com/2018/10/windows-10-notification-database/
        """
        target_tz = self.target.datetime.tzinfo

        for user, wpndatabase in self.wpndb_files:
            db = sqlite3.SQLite3(wpndatabase.open())
            handlers = {}

            if table := db.table("NotificationHandler"):
                for row in table.rows():
                    handlers[row["[RecordId]"]] = WpnDatabaseNotificationHandlerRecord(
                        created_time=datetime.datetime.strptime(row["[CreatedTime]"], "%Y-%m-%d %H:%M:%S").replace(
                            tzinfo=target_tz
                        ),
                        modified_time=datetime.datetime.strptime(row["[ModifiedTime]"], "%Y-%m-%d %H:%M:%S").replace(
                            tzinfo=target_tz
                        ),
                        id=row["[RecordId]"],
                        primary_id=row["[PrimaryId]"],
                        wns_id=row["[WNSId]"],
                        handler_type=row["[HandlerType]"],
                        wnf_event_name=row["[WNFEventName]"],
                        system_data_property_set=row["[SystemDataPropertySet]"],
                        _target=self.target,
                        _user=user,
                    )

            if table := db.table("Notification"):
                for row in table.rows():
                    record = WpnDatabaseNotificationRecord(
                        arrival_time=wintimestamp(row["[ArrivalTime]"]),
                        expiry_time=wintimestamp(row["[ExpiryTime]"]),
                        order=row["[Order]"],
                        id=row["[Id]"],
                        handler_id=row["[HandlerId]"],
                        activity_id=UUID(bytes=row["[ActivityId]"]),
                        type=row["[Type]"],
                        payload=row["[Payload]"],
                        payload_type=row["[PayloadType]"],
                        tag=row["[Tag]"],
                        group=row["[Group]"],
                        boot_id=row["[BootId]"],
                        expires_on_reboot=row["[ExpiresOnReboot]"] != "FALSE",
                        _target=self.target,
                        _user=user,
                    )
                    handler = handlers.get(row["[HandlerId]"])

                    if handler:
                        yield GroupedRecord("windows/notification/wpndatabase/grouped", [record, handler])
                    else:
                        yield record
