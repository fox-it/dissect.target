from pathlib import Path
from typing import BinaryIO, Iterator, Tuple

from dissect.esedb import esedb, table, record
from dissect.util.ts import wintimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.browsers.browser import GENERIC_HISTORY_RECORD_FIELDS, try_idna
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.plugins.general.users import UserDetails
from dissect.target.target import Target


IEBrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "browsers/ie/history", GENERIC_HISTORY_RECORD_FIELDS
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

        Yields BrowserHistoryRecords with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            hostname (string): The target hostname.
            browser (string): The browser from which the records are generated from.
            id (string): Record ID.
            url (uri): History URL.
            title (string): Page title.
            rev_host (string): Reverse hostname.
            lastvisited (datetime): Last visited date and time.
            visit_count (varint): Amount of visits.
            hidden (string): Hidden value.
            typed (string): Typed value.
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

                last_visited_time = (
                    wintimestamp(container_record.get("AccessedTime")) if container_record.get("AccessedTime") else None
                )

                yield IEBrowserHistoryRecord(
                    lastvisited=last_visited_time,
                    browser="iexplore",
                    id=container_record.get("EntryId"),
                    url=try_idna(url),
                    title=None,
                    rev_host=None,
                    visit_count=container_record.get("AccessCount"),
                    hidden=None,
                    typed=None,
                    source=str(cache_file),
                    _target=self.target,
                    _user=user,
                )
