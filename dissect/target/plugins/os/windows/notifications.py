import datetime
from uuid import UUID

from dissect.sql import sqlite3
from dissect.util.ts import wintimestamp
from flow.record import GroupedRecord

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import Plugin, export
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension


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


class NotificationsPlugin(Plugin):
    """Plugin that parses the notification databases on Windows 10 machines."""

    __namespace__ = "notifications"

    def __init__(self, target):
        super().__init__(target)
        self.wpndb_files = []
        self.appdb_files = []

        for user_details in target.user_details.all_with_home():
            notification_dir = user_details.home_path.joinpath("AppData/Local/Microsoft/Windows/Notifications")
            wpndb_file = notification_dir.joinpath("wpndatabase.db")
            appdb_file = notification_dir.joinpath("appdb.dat")

            if wpndb_file.exists():
                self.wpndb_files.append((user_details.user, wpndb_file))

            if appdb_file.exists():
                self.appdb_files.append((user_details.user, appdb_file))

    def check_compatible(self):
        if not self.wpndb_files and not self.appdb_files:
            raise UnsupportedPluginError("No wpndatabase.db or appdb.dat files found")

    @export(record=[WpnDatabaseNotificationRecord, WpnDatabaseNotificationHandlerRecord])
    def wpndatabase(self):
        """Returns Windows Notifications from wpndatabase.db (post Windows 10 Anniversary).

        Resources:
            - https://inc0x0.com/2018/10/windows-10-notification-database/
        """
        for user, wpndatabase in self.wpndb_files:
            db = sqlite3.SQLite3(wpndatabase.open())

            handlers = {}
            for row in db.table("NotificationHandler").rows():
                handlers[row["[RecordId]"]] = WpnDatabaseNotificationHandlerRecord(
                    created_time=datetime.datetime.strptime(row["[CreatedTime]"], "%Y-%m-%d %H:%M:%S"),
                    modified_time=datetime.datetime.strptime(row["[ModifiedTime]"], "%Y-%m-%d %H:%M:%S"),
                    id=row["[RecordId]"],
                    primary_id=row["[PrimaryId]"],
                    wns_id=row["[WNSId]"],
                    handler_type=row["[HandlerType]"],
                    wnf_event_name=row["[WNFEventName]"],
                    system_data_property_set=row["[SystemDataPropertySet]"],
                    _target=self.target,
                    _user=user,
                )

            for row in db.table("Notification").rows():
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
