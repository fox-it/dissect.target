from pathlib import Path
from typing import Iterator, Optional, Union

from dissect.thumbcache import Error, Thumbcache
from dissect.thumbcache.tools.extract_with_index import dump_entry_data_through_index

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export

GENERIC_THUMBCACHE_FIELDS = [
    ("string", "identifier"),
    ("string", "hash"),
    ("string", "extension"),
    ("varint", "data_size"),
    ("bytes", "header_checksum"),
    ("bytes", "data_checksum"),
    ("path", "path"),
]
IndexRecord = TargetRecordDescriptor(
    "windows/thumbcache/index",
    [
        ("string", "identifier"),
        ("boolean", "in_use"),
        ("varint", "flags"),
        ("datetime", "last_modified"),
        ("path", "path"),
    ],
)
ThumbcacheRecord = TargetRecordDescriptor("windows/thumbcache/thumbcache", GENERIC_THUMBCACHE_FIELDS)
IconcacheRecord = TargetRecordDescriptor("windows/thumbcache/iconcache", GENERIC_THUMBCACHE_FIELDS)


class ThumbcachePlugin(Plugin):
    __namespace__ = "thumbcache"

    def get_cache_paths(self) -> Iterator[TargetPath]:
        for user_details in self.target.user_details.all_with_home():
            cache_path = user_details.home_path / "appdata/local/microsoft/windows/explorer"
            if cache_path.exists():
                yield cache_path

    def check_compatible(self) -> None:
        for cache_path in self.get_cache_paths():
            if len(list(cache_path.glob("*_idx.db"))) > 0:
                return
        raise UnsupportedPluginError("There was no cache path for that plugin")

    def _create_entries(self, cache: Thumbcache, record_type: TargetRecordDescriptor):
        for path, entry in cache.entries():
            yield record_type(
                identifier=entry.identifier,
                hash=entry.hash,
                extension=entry.extension,
                header_checksum=entry.header_checksum,
                data_checksum=entry.data_checksum,
                path=path,
                data_size=len(entry.data),
            )
        for index_entry in cache.index_entries():
            yield IndexRecord(
                identifier=index_entry.identifier.hex(),
                in_use=index_entry.in_use(),
                flags=index_entry.flags,
                last_modified=index_entry.last_modified,
                path=cache.index_file,
            )

    def _parse_thumbcache(
        self,
        record_type: TargetRecordDescriptor,
        prefix: str,
        output_dir: Optional[Path],
    ) -> Iterator[Union[ThumbcacheRecord, IconcacheRecord, IndexRecord]]:
        for cache_path in self.get_cache_paths():
            try:
                if output_dir:
                    dump_entry_data_through_index(cache_path, output_dir, prefix)
                else:
                    cache = Thumbcache(cache_path, prefix=prefix)
                    yield from self._create_entries(cache, record_type)

            except Error as e:
                # A specific thumbcache exception occurred, log the error.
                self.target.log.error(e)
            except Exception as e:
                # A different exception occurred, log the exception.
                self.target.log.critical(e, exc_info=True)
                pass

    @arg("--output", "-o", dest="output_dir", type=Path, help="Path to extract thumbcache thumbnails to.")
    @export(record=[ThumbcacheRecord, IndexRecord])
    def thumbcache(self, output_dir: Optional[Path] = None) -> Iterator[Union[ThumbcacheRecord, IndexRecord]]:
        yield from self._parse_thumbcache(ThumbcacheRecord, "thumbcache", output_dir)

    @arg("--output", "-o", dest="output_dir", type=Path, help="Path to extract iconcache thumbnails to.")
    @export(record=[IconcacheRecord, IndexRecord])
    def iconcache(self, output_dir: Optional[Path] = None) -> Iterator[Union[IconcacheRecord, IndexRecord]]:
        yield from self._parse_thumbcache(IconcacheRecord, "iconcache", output_dir)
