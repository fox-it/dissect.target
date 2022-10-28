from typing import Iterator, Union

from dissect.thumbcache.exceptions import Error
from dissect.thumbcache.thumbcache import Thumbcache

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

GENERIC_THUMBCACHE_FIELDS = [
    ("string", "identifier"),
    ("string", "hash"),
    ("string", "extension"),
    ("varint", "data_size"),
    ("bytes", "header_checksum"),
    ("bytes", "data_checksum"),
    ("uri", "path"),
]
IndexRecord = TargetRecordDescriptor(
    "thumbcache/index",
    [
        ("string", "identifier"),
        ("boolean", "in_use"),
        ("varint", "flags"),
        ("datetime", "last_modified"),
        ("uri", "path"),
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
            if len(list(cache_path.glob("*_idx.db"))) == 0:
                raise UnsupportedPluginError("There was no cache path for that plugin")

    def _parse_thumbcache(
        self, record_type: TargetRecordDescriptor, prefix: str
    ) -> Iterator[Union[ThumbcacheRecord, IconcacheRecord, IndexRecord]]:
        for cache_path in self.get_cache_paths():
            try:
                cache = Thumbcache(cache_path, prefix=prefix)

                for path, entry in cache.entries():
                    yield record_type(
                        identifier=entry.identifier,
                        hash=entry.hash,
                        extension=entry.extension,
                        header_checksum=entry.header_checksum,
                        data_checksum=entry.data_checksum,
                        path=str(path),
                        data_size=len(entry.data),
                    )
                for index_entry in cache.index_entries():
                    yield IndexRecord(
                        identifier=index_entry.identifier.hex(),
                        in_use=index_entry.in_use(),
                        flags=index_entry.flags,
                        last_modified=index_entry.last_modified,
                        path=str(cache.index_file),
                    )
            except Error as e:
                # A specific thumbcache exception occurred, log the error.
                self.target.log.error(e)
            except Exception as e:
                # A different exception occurred, log the exception.
                self.target.log.critical(e, exc_info=True)
                pass

    @export(record=ThumbcacheRecord)
    def thumbcache(self) -> Iterator[ThumbcacheRecord]:
        yield from self._parse_thumbcache(ThumbcacheRecord, "thumbcache")

    @export(record=IconcacheRecord)
    def iconcache(self) -> Iterator[IconcacheRecord]:
        yield from self._parse_thumbcache(IconcacheRecord, "iconcache")
