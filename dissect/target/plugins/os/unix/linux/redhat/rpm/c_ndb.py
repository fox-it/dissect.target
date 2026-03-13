from __future__ import annotations

from dissect.cstruct import cstruct

# References:
# - https://github.com/rpm-software-management/rpm/blob/master/lib/backend/ndb/rpmpkg.c
ndb_def = """
#define NDB_HEADER_MAGIC            1349349458      // b"RpmP"
#define NDB_DB_VERSION              0
#define NDB_SLOT_MAGIC              1953459283      // b"Slot"
#define NDB_BLOB_MAGIC              1398959170      // b"BlbS"
#define NDB_SLOT_PAGE_SIZE          4096

struct Header {
    uint32      magic;
    uint32      version;
    uint32      generation;
    uint32      num_pages;
};

struct SlotEntry {
    uint32      magic;
    uint32      pkg_index;                          // 0 = empty, 1 = filled
    uint32      blk_offset;                         // points to Blob
    uint32      blk_count;
};

struct Blob {
    uint32      magic;
    uint32      pkg_index;
    uint32      checksum;                           // adler32 (rfc1950)
    uint32      size;
    // char     data[size];
    // char     tail[16];
};

#define NDB_BLOB_HEADER_SIZE        sizeof(Blob)
#define NDB_SLOT_ENTRIES_PER_PAGE   NDB_SLOT_PAGE_SIZE / sizeof(SlotEntry)

struct SlotPage {
    SlotEntry   entries[NDB_SLOT_ENTRIES_PER_PAGE]; // minus two for the first page
};
"""

c_ndb = cstruct(endian="<").load(ndb_def)
