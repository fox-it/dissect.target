from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree
from flow.record import GroupedRecord

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target
    from dissect.target.helpers.fsutil import TargetPath


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
    "unix/linux/recently_used/icon",
    [
        ("string", "type"),
        ("string", "href"),
        ("string", "name"),
    ],
)

RecentlyUsedApplicationRecord = TargetRecordDescriptor(
    "unix/linux/recently_used/application",
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


def parse_ts(target: Target, ts: str) -> datetime | None:
    """Parse timestamp format from xbel file

    Returns None if unable to parse the timestamp"""
    if ts is None:
        return None

    try:
        # datetime.fromisoformat() doesn't support the trailing Z in python <= 3.10
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as e:
        # Use None if we're unable to parse the timestamp
        target.log.warning("Could not parse timestamp %s, using None instead", ts)
        target.log.debug("", exc_info=e)
        return None


def parse_recently_used_xbel(
    target: Target, username: str, xbel_file: TargetPath
) -> Iterator[RecentlyUsedRecord | GroupedRecord] | None:
    with xbel_file.open() as fh:
        try:
            et = ElementTree.fromstring(fh.read(), forbid_dtd=True)
        except ParseError as e:
            target.log.warning("Could not parse %s, skipping", xbel_file)
            target.log.debug("", exc_info=e)
            return

        for bookmark in et.iter("bookmark"):
            # The spec says there should always be exactly one.
            # Ignore if there are fewer or more.
            mimetypes = bookmark.findall("./info/metadata/mime:mime-type", ns)
            if mimetypes and len(mimetypes) == 1:  # noqa SIM108
                mimetype = mimetypes[0].get("type")
            else:
                mimetype = None

            # This is just a list of names, GroupedRecords seem overkill
            groups = bookmark.findall("./info/metadata/bookmark:groups/bookmark:group", ns)
            group_list = ", ".join(group.text for group in groups)

            # There should be at most one "private" tag, but accept multiple
            private_entries = bookmark.findall("./info/metadata/bookmark:private", ns)
            private = len(private_entries) > 0

            cur = RecentlyUsedRecord(
                ts=parse_ts(target, bookmark.get("visited")),
                user=username,
                source=xbel_file,
                href=bookmark.get("href"),
                added=parse_ts(target, bookmark.get("added")),
                modified=parse_ts(target, bookmark.get("modified")),
                visited=parse_ts(target, bookmark.get("visited")),
                mimetype=mimetype,
                groups=group_list,
                private=private,
                _target=target,
            )
            yield cur

            # Icon is optional, spec says at most one.
            for icon in bookmark.findall("./info/metadata/bookmark:icon", ns):
                iconrecord = RecentlyUsedIconRecord(
                    type=icon.get("type"),
                    href=icon.get("href"),
                    name=icon.get("name"),
                )
                yield GroupedRecord("unix/linux/recently_used/icon", [cur, iconrecord])

            # Spec says there should be at least one application
            for app in bookmark.findall("./info/metadata/bookmark:applications/bookmark:application", ns):
                apprecord = RecentlyUsedApplicationRecord(
                    ts=parse_ts(target, app.get("modified")),
                    name=app.get("name"),
                    exec=app.get("exec"),
                    count=app.get("count"),
                )
                yield GroupedRecord("unix/linux/recently_used/application", [cur, apprecord])


class RecentlyUsedPlugin(Plugin):
    """Parse recently-used.xbel files on Gnome-based Linux Desktops.

    Based on the spec on https://www.freedesktop.org/wiki/Specifications/desktop-bookmark-spec/
    """

    FILEPATH = ".local/share/recently-used.xbel"

    def __init__(self, target: Target):
        super().__init__(target)
        self.users_files: list[tuple[str, TargetPath]] = []
        for user_details in self.target.user_details.all_with_home():
            xbel_file = user_details.home_path.joinpath(self.FILEPATH)
            if not xbel_file.exists():
                continue
            self.users_files.append((user_details.user, xbel_file))

    def check_compatible(self) -> None:
        if not len(self.users_files):
            raise UnsupportedPluginError("No recently-used.xbel files found")

    @export(record=RecentlyUsedRecord)
    def recently_used(self) -> Iterator[RecentlyUsedRecord | GroupedRecord]:
        """Parse recently-used.xbel files on Linux Desktops."""

        for user, xbel_file in self.users_files:
            yield from parse_recently_used_xbel(self.target, user.name, xbel_file)
