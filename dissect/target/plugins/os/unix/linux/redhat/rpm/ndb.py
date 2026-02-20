from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.linux.redhat.rpm.c_ndb import c_ndb

if TYPE_CHECKING:
    from collections.abc import Iterator
    from io import BytesIO


class NDB:
    """RedHat RPM NDB simplified database implementation.

    References:
        - https://github.com/rpm-software-management/rpm/blob/rpm-4.17.0-release/lib/backend/ndb/rpmpkg.c
    """

    def __init__(self, fh: BytesIO):
        self.fh = fh
        self.header = c_ndb.Header(fh)

        if self.header.magic != c_ndb.NDB_HEADER_MAGIC:
            raise ValueError(f"Invalid header magic {self.header.magic!r}")

        if self.header.version > c_ndb.NDB_DB_VERSION:
            raise ValueError(f"Unsupported database version {self.header.version!r}")

        if self.header.num_pages > 2048:
            raise ValueError(f"Slot page limit exeeded: {self.header.num_pages!r}")

        self.pages = [c_ndb.SlotPage(fh) for _ in range(self.header.num_pages)]

    def __repr__(self) -> str:
        return (
            f"<NDB fh={self.fh!r} "
            f"version={self.header.version} "
            f"generation={self.header.generation} "
            f"num_pages={self.header.num_pages}>"
        )

    def records(self) -> Iterator[bytes]:
        for page_num, page in enumerate(self.pages):
            for entry_num, entry in enumerate(page.entries):
                # The first slot of the first page is actually the header.
                if page_num == 0 and entry_num == 0:
                    continue

                if entry_num > c_ndb.NDB_SLOT_ENTRIES_PER_PAGE - 2:
                    continue

                if entry.magic != c_ndb.NDB_SLOT_MAGIC:
                    raise ValueError(f"Invalid slot magic for entry (page={page_num} entry={entry_num}) {entry!r}")

                # This slot is empty and does not contain a pointer to a blob.
                if entry.pkg_index == 0:
                    continue

                self.fh.seek(entry.blk_offset * c_ndb.NDB_BLOB_HEADER_SIZE)
                blob = c_ndb.Blob(self.fh)

                if blob.magic != c_ndb.NDB_BLOB_MAGIC:
                    raise ValueError(f"Invalid blob magic for blob {blob!r}")

                if blob.pkg_index != entry.pkg_index:
                    raise ValueError(f"Package index mismatch for {blob!r} and {entry!r}")

                yield self.fh.read(blob.size)
