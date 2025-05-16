import logging
from datetime import datetime
from typing import Iterator, Union
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree
from flow.record import GroupedRecord

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

log = logging.getLogger(__name__)


RecentlyUsedRecord = TargetRecordDescriptor(
    "unix/linux/recently_used",
    [
        ("datetime", "ts"),
        ("string", "user"),
        ("string", "source"),
        ("string", "href"),
        ("datetime", "added"),
        ("datetime", "modified"),
        ("datetime", "visited"),
        ("string", "mimetype"),
        ("string", "groups"),
        ("boolean", "private"),
    ],
)

RecentlyUsedIconRecord = TargetRecordDescriptor(
    "unix/linux/recently_used_icon",
    [
        ("string", "type"),
        ("string", "href"),
        ("string", "name"),
    ],
)

RecentlyUsedApplicationRecord = TargetRecordDescriptor(
    "unix/linux/recently_used_application",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("string", "exec"),
        ("varint", "count"),
    ],
)
ns = {
    "bookmark": "http://www.freedesktop.org/standards/desktop-bookmarks",
    "mime": "http://www.freedesktop.org/standards/shared-mime-info",
}


def parse_ts(ts: str):
    """Parse timestamp format from xbel file

    Returns None if unable to parse the timestamp"""
    if ts is None:
        return None

    try:
        # datetime.fromisoformat() doesn´t support the trailing Z in python <= 3.10
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as e:
        # Use None if we're unable to parse the timestamp
        log.warning(f"Could not parse timestamp {ts}, using None instead")
        log.debug("", exc_info=e)
        return None


def parse_recently_used_xbel(target: Target, username: str, xbel_file: TargetPath):
    with xbel_file.open() as fh:
        try:
            et = ElementTree.fromstring(fh.read(), forbid_dtd=True)
        except ParseError as e:
            log.warning(f"Could not parse {xbel_file}, skipping")
            log.debug("", exc_info=e)
            return

        for b in et.iter("bookmark"):
            # The spec says there should always be exactly one.
            # Ignore if there are fewer or more.
            mimetypes = b.findall("./info/metadata/mime:mime-type", ns)
            if mimetypes and len(mimetypes) == 1:
                mimetype = mimetypes[0].get("type")
            else:
                mimetype = None

            # This is just a list of names, GroupedRecords seem overkill
            groups = b.findall("./info/metadata/bookmark:groups/bookmark:group", ns)
            group_list = ", ".join(group.text for group in groups)

            # There should be at most one "private" tag, but accept multiple
            private_entries = b.findall("./info/metadata/bookmark:private", ns)
            private = len(private_entries) > 0

            cur = RecentlyUsedRecord(
                ts=parse_ts(b.get("visited")),
                user=username,
                source=xbel_file,
                href=b.get("href"),
                added=parse_ts(b.get("added")),
                modified=parse_ts(b.get("modified")),
                visited=parse_ts(b.get("visited")),
                mimetype=mimetype,
                groups=group_list,
                private=private,
                _target=target,
            )
            yield cur

            # Icon is optional, spec says at most one.
            icons = b.findall("./info/metadata/bookmark:icon", ns)
            for icon in icons:
                iconrecord = RecentlyUsedIconRecord(
                    type=icon.get("type"),
                    href=icon.get("href"),
                    name=icon.get("name"),
                )
                yield GroupedRecord("unix/linux/recently_used/grouped", [cur, iconrecord])

            # Spec says there should be at least one application
            apps = b.findall("./info/metadata/bookmark:applications/bookmark:application", ns)
            for app in apps:
                apprecord = RecentlyUsedApplicationRecord(
                    ts=parse_ts(app.get("modified")),
                    name=app.get("name"),
                    exec=app.get("exec"),
                    count=app.get("count"),
                )
                yield GroupedRecord("unix/linux/recently_used/grouped", [cur, apprecord])


class RecentlyUsedPlugin(Plugin):
    """Parse recently-used.xbel files on Gnome-based Linux Desktops.

    Based on the spec on https://www.freedesktop.org/wiki/Specifications/desktop-bookmark-spec/
    """

    FILEPATH = ".local/share/recently-used.xbel"

    def __init__(self, target: Target):
        super().__init__(target)
        self.users_files = []
        for user_details in self.target.user_details.all_with_home():
            xbel_file = user_details.home_path.joinpath(self.FILEPATH)
            if not xbel_file.exists():
                continue
            self.users_files.append((user_details.user, xbel_file))

    def check_compatible(self) -> None:
        if not len(self.users_files):
            raise UnsupportedPluginError("No recently-used.xbel files found")

    @export(record=RecentlyUsedRecord)
    def recently_used(self) -> Iterator[Union[RecentlyUsedRecord, GroupedRecord]]:
        """Parse recently-used.xbel files on Linux Desktops."""

        for user, xbel_file in self.users_files:
            for record in parse_recently_used_xbel(self.target, user.name, xbel_file):
                yield record
