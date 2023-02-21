from pathlib import Path
from typing import BinaryIO, Iterator, Tuple

from dissect.esedb import esedb, record, table
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.browsers.browser import (
    GENERIC_DOWNLOAD_RECORD_FIELDS,
    GENERIC_HISTORY_RECORD_FIELDS,
    try_idna,
)
from dissect.target.plugins.general.users import UserDetails
from dissect.target.target import Target
from dissect.util.ts import wintimestamp


class WebCache:
    """Class for opening and pre-processing IE WebCache file."""

    def __init__(self, target: Target, fh: BinaryIO):
        self.target = target
        self.db = esedb.EseDB(fh)

    def find_containers(self, name: str) -> table.Table:
        """Look up ContainerId from name

        Args:
            name: A String with the container name

        Yields:
            A String with ContainerId.
        """
        try:
            for container_record in self.db.table("Containers").records():
                if record_name := container_record.get("Name"):
                    record_name = record_name.rstrip("\00").lower()
                    if record_name == name.lower():
                        container_id = container_record.get("ContainerId")
                        yield self.db.table(f"Container_{container_id}")
        except KeyError:
            pass

    def _iter_records(self, name: str) -> Iterator[record.Record]:
        """Yield records from a Webcache container.

        Args:
            name: A String with the container name.

        Yields:
            Records from specified Webcache container.
        """
        for container in self.find_containers(name):
            try:
                yield from container.records()
            except Exception as e:
                self.target.log.warning("Error iterating IExplore container %s", container, exc_info=e)
                continue

    def history(self) -> Iterator[record.Record]:
        """Yield records from the history webcache container."""
        yield from self._iter_records("history")

    def downloads(self) -> Iterator[record.Record]:
        """Yield records from the iedownload webcache container."""
        yield from self._iter_records("iedownload")


class InternetExplorerPlugin(Plugin):
    """Internet explorer browser plugin."""

    __namespace__ = "iexplore"

    DIRS = [
        "AppData/Local/Microsoft/Windows/WebCache",
    ]
    CACHE_FILENAME = "WebCacheV01.dat"
    IE_BROWSER_HISTORY_RECORD = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/ie/history", GENERIC_HISTORY_RECORD_FIELDS
    )
    IE_BROWSER_DOWNLOAD_RECORD = create_extended_descriptor([UserRecordDescriptorExtension])(
        "browser/ie/download", GENERIC_DOWNLOAD_RECORD_FIELDS
    )

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
        """Perform a compatibility check with the target.
        This function checks if any of the supported browser directories
        exists. Otherwise it should raise an ``UnsupportedPluginError``.
        Raises:
            UnsupportedPluginError: If the plugin could not be loaded.
        """
        if not len(self.users_dirs):
            raise UnsupportedPluginError("No Internet Explorer directories found")

    def open_cache(self, cdir) -> WebCache:
        """Opens the Internet Explorer esedb file containing the history and download data.

        Args:
            cidr: Path to the cache file.

        Returns:
            WebCache object
        """
        self.cache_file = cdir.joinpath(self.CACHE_FILENAME)
        if self.cache_file.exists():
            return WebCache(self.target, self.cache_file.open())

    @export(record=IE_BROWSER_HISTORY_RECORD)
    def history(self) -> Iterator[IE_BROWSER_HISTORY_RECORD]:
        """Return browser history records from Internet Explorer.

        Yields IE_BROWSER_HISTORY_RECORD with the following fields:
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
            cache: WebCache = self.open_cache(cdir)
            if not cache:
                continue

            for container_record in cache.history():
                if not container_record.get("Url"):
                    continue

                _, _, url = container_record.get("Url", "").rstrip("\x00").partition("@")

                ts = None
                if accessed_time := container_record.get("AccessedTime"):
                    ts = wintimestamp(accessed_time)

                yield self.IE_BROWSER_HISTORY_RECORD(
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
                    source=str(self.cache_file),
                    _target=self.target,
                    _user=user,
                )

    @export(record=IE_BROWSER_DOWNLOAD_RECORD)
    def downloads(self) -> Iterator[IE_BROWSER_DOWNLOAD_RECORD]:
        """Return browser downloads records from Internet Explorer.

        Yields IE_BROWSER_DOWNLOAD_RECORD with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts_start (datetime): Download start timestamp.
            ts_end (datetime): Download end timestamp.
            browser (string): The browser from which the records are generated from.
            id (string): Record ID.
            path (string): Download path.
            url (uri): Download URL.
            size (varint): Download file size.
            state (varint): Download state number.
            source: (path): The source file of the history record.
        """
        for user, cdir in self.users_dirs:
            cache: WebCache = self.open_cache(cdir)
            if not cache:
                continue

            for r in cache.downloads():
                response_headers = r.ResponseHeaders.decode("utf-16-le", errors="ignore")
                ref_url, mime_type, temp_download_path, down_url, down_path = response_headers.split("\x00")[-6:-1]

                yield self.IE_BROWSER_DOWNLOAD_RECORD(
                    ts_start=None,
                    ts_end=wintimestamp(r.AccessedTime),
                    browser="iexplore",
                    id=r.EntryId,
                    path=down_path,
                    url=down_url,
                    size=None,
                    state=None,
                    source=str(self.cache_file),
                    _target=self.target,
                    _user=user,
                )
