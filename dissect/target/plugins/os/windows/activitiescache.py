from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.sql import sqlite3
from dissect.util.ts import from_unix

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

    from dissect.target.target import Target

ActivitiesCacheRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/activitiescache",
    [
        ("datetime", "start_time"),
        ("datetime", "end_time"),
        ("datetime", "last_modified_time"),
        ("datetime", "last_modified_on_client"),
        ("datetime", "original_last_modified_on_client"),
        ("datetime", "expiration_time"),
        ("string", "app_id"),
        ("string", "enterprise_id"),
        ("string", "app_activity_id"),
        ("string", "group_app_activity_id"),
        ("string", "group"),
        ("uint32", "activity_type"),
        ("uint32", "activity_status"),
        ("uint32", "priority"),
        ("uint32", "match_id"),
        ("uint32", "etag"),
        ("string", "tag"),
        ("boolean", "is_local_only"),
        ("datetime", "created_in_cloud"),
        ("string", "platform_device_id"),
        ("string", "package_id_hash"),
        ("bytes", "id"),
        ("string", "payload"),
        ("string", "original_payload"),
        ("string", "clipboard_payload"),
    ],
)


class ActivitiesCachePlugin(Plugin):
    """Plugin that parses the ActivitiesCache.db on newer Windows 10 machines.

    References:
        - https://www.cclsolutionsgroup.com/resources/technical-papers
        - https://salt4n6.com/2018/05/03/windows-10-timeline-forensic-artefacts/
    """

    def __init__(self, target: Target):
        super().__init__(target)
        self.cachefiles = []

        for user_details in target.user_details.all_with_home():
            full_path = user_details.home_path.joinpath("AppData/Local/ConnectedDevicesPlatform")
            cache_files = full_path.glob("*/ActivitiesCache.db")
            for cache_file in cache_files:
                if cache_file.exists():
                    self.cachefiles.append((user_details.user, cache_file))

    def check_compatible(self) -> None:
        if len(self.cachefiles) == 0:
            raise UnsupportedPluginError("No ActiviesCache.db files found")

    @export(record=ActivitiesCacheRecord)
    def activitiescache(self) -> Iterator[ActivitiesCacheRecord]:
        """Return ActivitiesCache.db database content.

        The Windows Activities Cache database keeps track of activity on a device, such as application and services
        usage, files opened, and websites browsed. This database file can therefore be used to create a system timeline.
        It has first been used on Windows 10 1803.

        Currently only puts the database records straight into Flow Records. Ideally
        we do some additional parsing on this later.

        References:
            - https://artifacts-kb.readthedocs.io/en/latest/sources/windows/ActivitiesCacheDatabase.html
            - https://salt4n6.com/2018/05/03/windows-10-timeline-forensic-artefacts/

        Yields ActivitiesCacheRecords with the following fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            start_time (datetime): StartTime field.
            end_time (datetime): EndTime field.
            last_modified_time (datetime): LastModifiedTime field.
            last_modified_on_client (datetime): LastModifiedOnClient field.
            original_last_modified_on_client (datetime): OriginalLastModifiedOnClient field.
            expiration_time (datetime): ExpirationTime field.
            app_id (string): AppId field, JSON string containing multiple types of app name definitions.
            enterprise_id (string): EnterpriseId field.
            app_activity_id (string): AppActivityId field.
            group_app_activity_id (string): GroupAppActivityId field.
            group (string): Group field.
            activity_type (int): ActivityType field.
            activity_status (int): ActivityStatus field.
            priority (int): Priority field.
            match_id (int): MatchId field.
            etag (int): ETag field.
            tag (string): Tag field.
            is_local_only (boolean): IsLocalOnly field.
            created_in_cloud (datetime): CreatedInCloud field.
            platform_device_id (string): PlatformDeviceId field.
            package_id_hash (string): PackageIdHash field.
            id (bytes): Id field.
            payload (string): Payload field. JSON string containing payload data, varies per type.
            original_payload (string): OriginalPayload field.
            clipboard_payload (string): ClipboardPayload field.
        """
        for user, cache_file in self.cachefiles:
            fh = cache_file.open()
            db = sqlite3.SQLite3(fh)

            if table := db.table("Activity"):
                for r in table.rows():
                    yield ActivitiesCacheRecord(
                        start_time=mkts(r["[StartTime]"]),
                        end_time=mkts(r["[EndTime]"]),
                        last_modified_time=mkts(r["[LastModifiedTime]"]),
                        last_modified_on_client=mkts(r["[LastModifiedOnClient]"]),
                        original_last_modified_on_client=mkts(r["[OriginalLastModifiedOnClient]"]),
                        expiration_time=mkts(r["[ExpirationTime]"]),
                        app_id=r["[AppId]"],
                        enterprise_id=r["[EnterpriseId]"],
                        app_activity_id=r["[AppActivityId]"],
                        group_app_activity_id=r["[GroupAppActivityId]"],
                        group=r["[Group]"],
                        activity_type=r["[ActivityType]"],
                        activity_status=r["[ActivityStatus]"],
                        priority=r["[Priority]"],
                        match_id=r["[MatchId]"],
                        etag=r["[ETag]"],
                        tag=r["[Tag]"],
                        is_local_only=r["[IsLocalOnly]"],
                        created_in_cloud=r["[CreatedInCloud]"],
                        platform_device_id=r["[PlatformDeviceId]"],
                        package_id_hash=r["[PackageIdHash]"],
                        id=r["[Id]"],
                        payload=r["[Payload]"],
                        original_payload=r["[OriginalPayload]"],
                        clipboard_payload=r["[ClipboardPayload]"],
                        _target=self.target,
                        _user=user,
                    )


def mkts(ts: int) -> datetime | None:
    """Timestamps inside ActivitiesCache.db are stored in a Unix-like format.

    Source: https://salt4n6.com/2018/05/03/windows-10-timeline-forensic-artefacts/
    """
    return from_unix(ts) if ts else None
