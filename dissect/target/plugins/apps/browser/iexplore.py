from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

from dissect.esedb import esedb, record, table
from dissect.esedb.exceptions import KeyNotFoundError
from dissect.util.ts import wintimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.browser.browser import (
    GENERIC_DOWNLOAD_RECORD_FIELDS,
    GENERIC_HISTORY_RECORD_FIELDS,
    BrowserPlugin,
    try_idna,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target


class WebCache:
    """Class for opening and pre-processing IE WebCache file."""

    def __init__(self, target: Target, fh: BinaryIO):
        self.target = target
        self.db = esedb.EseDB(fh)

    def find_containers(self, name: str) -> Iterator[table.Table]:
        """Look up all ``ContainerId`` values for a given container name.

        Args:
            name: The container name to look up all container IDs of.

        Yields:
            All ``ContainerId`` values for the requested container name.
        """
        try:
            table = self.db.table("Containers")

            for container_record in table.records():
                if record_name := container_record.get("Name"):
                    record_name = record_name.rstrip("\00").lower()
                    if record_name == name.lower():
                        container_id = container_record.get("ContainerId")
                        yield self.db.table(f"Container_{container_id}")

        except KeyError as e:
            self.target.log.warning("Exception while parsing EseDB Containers table")
            self.target.log.debug("", exc_info=e)

    def _iter_records(self, name: str) -> Iterator[record.Record]:
        """Yield records from a Webcache container.

        Args:
            name: The container name.

        Yields:
            Records from specified Webcache container.
        """
        for container in self.find_containers(name):
            try:
                yield from container.records()
            except Exception as e:  # noqa: PERF203
                self.target.log.warning("Error iterating IExplore container %s", container)
                self.target.log.debug("", exc_info=e)
                continue

    def history(self) -> Iterator[record.Record]:
        """Yield records from the history webcache container."""
        yield from self._iter_records("history")

    def downloads(self) -> Iterator[record.Record]:
        """Yield records from the iedownload webcache container."""
        yield from self._iter_records("iedownload")

    def cookies(self) -> None:
        raise NotImplementedError("Cookies plugin is not implemented for Internet Explorer yet")


class InternetExplorerPlugin(BrowserPlugin):
    """Internet explorer browser plugin."""

    __namespace__ = "iexplore"

    DIRS = ("AppData/Local/Microsoft/Windows/WebCache",)

    CACHE_FILENAME = "WebCacheV01.dat"

    BrowserHistoryRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/ie/history", GENERIC_HISTORY_RECORD_FIELDS
    )

    BrowserDownloadRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/ie/download", GENERIC_DOWNLOAD_RECORD_FIELDS
    )

    def __init__(self, target: Target):
        super().__init__(target)

        self.users_dirs: list[tuple[UserDetails, Path]] = []
        for user_details in self.target.user_details.all_with_home():
            for ie_dir in self.DIRS:
                cdir = user_details.home_path.joinpath(ie_dir)
                if not cdir.exists():
                    continue
                self.users_dirs.append((user_details.user, cdir))

    def check_compatible(self) -> None:
        if not len(self.users_dirs):
            raise UnsupportedPluginError("No Internet Explorer directories found")

    def _iter_cache(self) -> Iterator[WebCache]:
        """Yield open IE Webcache files.

        Args:
            filename: Name of the Webcache file.

        Yields:
            Open Webcache file.

        Raises:
            FileNoteFoundError: If the webcache file could not be found.
        """
        for user, cdir in self.users_dirs:
            cache_file = cdir.joinpath(self.CACHE_FILENAME)
            try:
                yield user, cache_file, WebCache(self.target, cache_file.open())
            except FileNotFoundError:
                self.target.log.warning("Could not find %s file: %s", self.CACHE_FILENAME, cache_file)

    @export(record=BrowserHistoryRecord)
    def history(self) -> Iterator[BrowserHistoryRecord]:
        """Return browser history records from Internet Explorer.

        Yields BrowserHistoryRecord with the following fields:

        .. code-block:: text

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
        for user, cache_file, cache in self._iter_cache():
            for container_record in cache.history():
                if not container_record.get("Url"):
                    continue

                _, _, url = container_record.get("Url", "").rstrip("\x00").partition("@")

                ts = None
                if accessed_time := container_record.get("AccessedTime"):
                    ts = wintimestamp(accessed_time)

                yield self.BrowserHistoryRecord(
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
                    source=cache_file,
                    _target=self.target,
                    _user=user,
                )

    @export(record=BrowserDownloadRecord)
    def downloads(self) -> Iterator[BrowserDownloadRecord]:
        """Return browser downloads records from Internet Explorer.

        Yields BrowserDownloadRecord with the following fields:

        .. code-block:: text

            ts_start (datetime): Download start timestamp.
            ts_end (datetime): Download end timestamp.
            browser (string): The browser from which the records are generated from.
            id (string): Record ID.
            path (string): Download path.
            url (uri): Download URL.
            size (varint): Download file size.
            state (varint): Download state number.
            source: (path): The source file of the download record.
        """
        for user, cache_file, cache in self._iter_cache():
            for container_record in cache.downloads():
                down_path = None
                down_url = None
                ts_end = wintimestamp(container_record.AccessedTime) if container_record.AccessedTime else None

                try:
                    response_headers = container_record.ResponseHeaders.decode("utf-16-le", errors="ignore")
                    # Not used here, but [-6:-3] should give: ref_url, mime_type, temp_download_path
                    down_url, down_path = response_headers.split("\x00")[-3:-1]
                except (AttributeError, KeyNotFoundError) as e:
                    self.target.log.error("Error parsing response headers: %s", e)  # noqa: TRY400
                    self.target.log.debug("", exc_info=e)

                yield self.BrowserDownloadRecord(
                    ts_start=None,
                    ts_end=ts_end,
                    browser="iexplore",
                    id=container_record.EntryId,
                    path=self.target.fs.path(down_path) if down_path else None,
                    url=down_url,
                    size=None,
                    state=None,
                    source=cache_file,
                    _target=self.target,
                    _user=user,
                )
