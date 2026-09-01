from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


SharedFileListRecord = TargetRecordDescriptor(
    "macos/sharedfilelist/entries",
    [
        ("string", "list_type"),
        ("string", "item_path"),
        ("string", "special_id"),
        ("string", "uuid"),
        ("varint", "visibility"),
        ("string[]", "bookmark_strings"),
        ("path", "source"),
    ],
)


class SharedFileListPlugin(Plugin):
    """Plugin to parse macOS SharedFileList (.sfl3) files.

    Parses Finder sidebar favorites, recent applications, recent documents,
    favorite volumes, project items, and iCloud items from:
    ~/Library/Application Support/com.apple.sharedfilelist/*.sfl3

    These are NSKeyedArchiver binary plists containing bookmark data that
    references files, folders, volumes, and special locations.
    """

    __namespace__ = "sharedfilelist"

    SFL_GLOBS = [
        "Users/*/Library/Application Support/com.apple.sharedfilelist/*.sfl3",
        "Users/*/Library/Application Support/com.apple.sharedfilelist/*.sfl4",
    ]

    # Map filename patterns to human-readable list types
    LIST_TYPES = {
        "FavoriteItems": "favorite_items",
        "FavoriteVolumes": "favorite_volumes",
        "RecentApplications": "recent_applications",
        "RecentDocuments": "recent_documents",
        "ProjectsItems": "project_items",
        "iCloudItems": "icloud_items",
    }

    def __init__(self, target):
        super().__init__(target)
        self._paths = []
        for pattern in self.SFL_GLOBS:
            self._paths.extend(self.target.fs.path("/").glob(pattern))

    def check_compatible(self) -> None:
        if not self._paths:
            raise UnsupportedPluginError("No SharedFileList .sfl3/.sfl4 files found")

    def _resolve(self, objects, uid):
        if isinstance(uid, plistlib.UID):
            return objects[uid]
        return uid

    def _get_list_type(self, path):
        """Derive list type from filename."""
        name = str(path).rsplit("/", 1)[-1]
        for pattern, label in self.LIST_TYPES.items():
            if pattern in name:
                return label
        # Fallback: strip prefix and suffix
        name = name.replace("com.apple.LSSharedFileList.", "").replace(".sfl3", "").replace(".sfl4", "")
        return name

    def _extract_bookmark_strings(self, bdata):
        """Extract readable strings from Apple bookmark binary data."""
        text = bdata.decode("latin-1")
        parts = text.split("\x00")
        return [p.strip() for p in parts if len(p.strip()) >= 2 and all(32 <= ord(c) < 127 for c in p.strip())]

    def _build_path(self, strings):
        """Build a filesystem path from bookmark string components."""
        path_parts = []
        for s in strings:
            if s.startswith(("file://", "nwnode://", "com-apple-sfl://", "x-apple-findertag:")):
                break
            path_parts.append(s)
        if path_parts:
            return "/" + "/".join(path_parts)
        # If no path components, check for URL-like strings
        for s in strings:
            if s.startswith(("nwnode://", "com-apple-sfl://", "x-apple-findertag:")):
                return s
        return ""

    def _parse_sfl3(self, path):
        """Parse an sfl3 file and yield item dicts."""
        try:
            with path.open("rb") as fh:
                data = plistlib.loads(fh.read())
        except Exception:
            return

        objects = data.get("$objects", [])

        def r(uid):
            return self._resolve(objects, uid)

        # Root is a dict with "items" and "properties" keys
        root = r(plistlib.UID(1))
        if not isinstance(root, dict) or "NS.keys" not in root:
            return

        root_keys = [r(k) for k in root["NS.keys"]]
        root_vals = root["NS.objects"]
        root_dict = dict(zip(root_keys, root_vals))

        items_uid = root_dict.get("items")
        if items_uid is None:
            return

        items_array = r(items_uid)
        if not isinstance(items_array, dict) or "NS.objects" not in items_array:
            return

        for uid in items_array["NS.objects"]:
            item = r(uid)
            if not isinstance(item, dict) or "NS.keys" not in item:
                continue

            keys = [r(k) for k in item["NS.keys"]]
            vals = [r(v) for v in item["NS.objects"]]
            d = dict(zip(keys, vals))

            # Extract bookmark data
            braw = d.get("Bookmark", {})
            if isinstance(braw, dict) and "NS.data" in braw:
                bdata = r(braw["NS.data"])
            elif isinstance(braw, bytes):
                bdata = braw
            else:
                bdata = b""

            strings = self._extract_bookmark_strings(bdata) if bdata else []
            item_path = self._build_path(strings)

            # Get special identifier from CustomItemProperties
            special_id = ""
            custom = d.get("CustomItemProperties", {})
            if isinstance(custom, dict) and "NS.keys" in custom:
                ck = [r(k) for k in custom["NS.keys"]]
                cv = [r(v) for v in custom["NS.objects"]]
                cd = dict(zip(ck, cv))
                special_id = cd.get("com.apple.LSSharedFileList.SpecialItemIdentifier", "")

            yield {
                "item_path": item_path,
                "special_id": str(special_id),
                "uuid": str(d.get("uuid", "")),
                "visibility": d.get("visibility", 0),
                "strings": strings,
            }

    def _yield_records(self, list_filter=None):
        """Yield records, optionally filtering by list type."""
        for path in self._paths:
            list_type = self._get_list_type(path)
            if list_filter and list_type != list_filter:
                continue

            try:
                for entry in self._parse_sfl3(path):
                    yield SharedFileListRecord(
                        list_type=list_type,
                        item_path=entry["item_path"],
                        special_id=entry["special_id"],
                        uuid=entry["uuid"],
                        visibility=entry["visibility"],
                        bookmark_strings=entry["strings"],
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing %s: %s", path, e)

    @export(record=SharedFileListRecord)
    def all(self) -> Iterator[SharedFileListRecord]:
        """Parse all SharedFileList .sfl3 files."""
        yield from self._yield_records()

    @export(record=SharedFileListRecord)
    def favorites(self) -> Iterator[SharedFileListRecord]:
        """Parse Finder sidebar favorite items."""
        yield from self._yield_records("favorite_items")

    @export(record=SharedFileListRecord)
    def volumes(self) -> Iterator[SharedFileListRecord]:
        """Parse favorite volumes (mounted drives, network shares)."""
        yield from self._yield_records("favorite_volumes")

    @export(record=SharedFileListRecord)
    def recent_apps(self) -> Iterator[SharedFileListRecord]:
        """Parse recently launched applications."""
        yield from self._yield_records("recent_applications")

    @export(record=SharedFileListRecord)
    def recent_docs(self) -> Iterator[SharedFileListRecord]:
        """Parse recently opened documents."""
        yield from self._yield_records("recent_documents")

    @export(record=SharedFileListRecord)
    def projects(self) -> Iterator[SharedFileListRecord]:
        """Parse Finder project/tag items."""
        yield from self._yield_records("project_items")
