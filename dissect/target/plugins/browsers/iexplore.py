from pathlib import Path
from typing import BinaryIO, Iterator, Tuple

from dissect.esedb import esedb, record, table
from dissect.util.ts import wintimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.browsers.browser import (
    GENERIC_HISTORY_RECORD_FIELDS,
    try_idna,
)
from dissect.target.plugins.general.users import UserDetails
from dissect.target.target import Target

IEBrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "browser/ie/history", GENERIC_HISTORY_RECORD_FIELDS
)


class WebCache:
    def __init__(self, target: Target, fh: BinaryIO):
        self.target = target
        self.db = esedb.EseDB(fh)

    def find_containers(self, name: str) -> table.Table:
        try:
            for container_record in self.db.table("Containers").records():
                record_name = container_record.get("Name")
                record_name = record_name.rstrip("\00").lower()
                if record_name == name.lower():
                    container_id = container_record.get("ContainerId")
                    yield self.db.table(f"Container_{container_id}")
        except KeyError:
            pass

    def _iter_records(self, name: str) -> Iterator[record.Record]:
        for container in self.find_containers(name):
            try:
                yield from container.records()
            except Exception as e:
                self.target.log.warning("Error iterating IExplore container %s", container, exc_info=e)
                continue

    def history(self) -> Iterator[record.Record]:
        yield from self._iter_records("history")


class InternetExplorerPlugin(Plugin):
    """Internet explorer browser plugin."""

    __namespace__ = "iexplore"

    DIRS = [
        "AppData/Local/Microsoft/Windows/WebCache",
    ]

    CACHE_FILENAME = "WebCacheV01.dat"

    def __init__(self, target: Target):
        super().__init__(target)

        self.users_dirs: list[Tuple[UserDetails, Path]] = []
        for user_details in self.target.user_details.all_with_home():
            for ie_dir in self.DIRS:
                cdir = user_details.home_path.joinpath(ie_dir)
                if not cdir.exists():
                    continue
                self.users_dirs.append((user_details.user, cdir))

    def check_compatible(self) -> bool:
        if not len(self.users_dirs):
            raise UnsupportedPluginError("No Internet Explorer directories found")

    @export(record=IEBrowserHistoryRecord)
    def history(self) -> Iterator[IEBrowserHistoryRecord]:
        """Return browser history records from Internet Explorer.

        Yields IEBrowserHistoryRecord with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): Visit timestamp.
            browser (string): The browser from which the records are generated from.
            id (string): Record ID.
            url (uri): History URL.
            title (string): Page title.
            description (string): Page description.
            rev_host (string): Reverse hostname.
            visit_type (varint): Visit type.
            visit_count (varint): Amount of visits.
            hidden (string): Hidden value.
            typed (string): Typed value.
            session (varint): Session value.
            from_visit (varint): Record ID of the "from" visit.
            from_url (uri): URL of the "from" visit.
            source: (path): The source file of the history record.
        """
        for user, cdir in self.users_dirs:
            cache_file = cdir.joinpath(self.CACHE_FILENAME)
            if not cache_file.exists():
                continue

            cache = WebCache(self.target, cache_file.open())
            for container_record in cache.history():
                if not container_record.get("Url"):
                    continue

                _, _, url = container_record.get("Url", "").rstrip("\x00").partition("@")

                ts = None
                if accessed_time := container_record.get("AccessedTime"):
                    ts = wintimestamp(accessed_time)

                yield IEBrowserHistoryRecord(
                    ts=ts,
                    browser="iexplore",
                    id=container_record.get("EntryId"),
                    url=try_idna(url),
                    title=None,
                    description=None,
                    rev_host=None,
                    visit_type=None,
                    visit_count=container_record.get("AccessCount"),
                    hidden=None,
                    typed=None,
                    session=None,
                    from_visit=None,
                    from_url=None,
                    source=str(cache_file),
                    _target=self.target,
                    _user=user,
                )
