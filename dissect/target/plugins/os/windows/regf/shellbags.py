import io
import logging
import uuid

from dissect import cstruct
from dissect.util.ts import dostimestamp

from dissect.target.exceptions import RegistryKeyNotFoundError, UnsupportedPluginError
from dissect.target.helpers import shell_folder_ids
from dissect.target.helpers.descriptor_extensions import (
    RegistryRecordDescriptorExtension,
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

log = logging.getLogger(__name__)

bag_def = """
enum ROOTFOLDER_ID : uint8 {
    INTERNET_EXPLORER   = 0x00,
    LIBRARIES           = 0x42,
    USERS               = 0x44,
    MY_DOCUMENTS        = 0x48,
    MY_COMPUTER         = 0x50,
    NETWORK             = 0x58,
    RECYCLE_BIN         = 0x60,
    INTERNET_EXPLORER   = 0x68,
    UNKNOWN             = 0x70,
    MY_GAMES            = 0x80
};

struct SHITEM_UNKNOWN0 {
    uint16  size;
    uint8   type;
};

struct SHITEM_UNKNOWN1 {
    uint16  size;
    uint8   type;
};

struct SHITEM_ROOT_FOLDER {
    uint16          size;
    uint8           type;
    ROOTFOLDER_ID   folder_id;
    char            guid[16];
};

struct SHITEM_VOLUME {
    uint16  size;
    uint8   type;
};

struct SHITEM_FILE_ENTRY {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint32  file_size;
    uint32  modification_time;
    uint16  file_attribute_flags;
};

struct SHITEM_NETWORK {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint8   flags;
    char    location[];
};

struct SHITEM_COMPRESSED_FOLDER {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint16  unk1;
};

struct SHITEM_URI {
    uint16  size;
    uint8   type;
    uint8   flags;
    uint16  data_size;
};

struct SHITEM_CONTROL_PANEL {
    uint16  size;
    uint8   type;
    uint8   unk0;
    char    unk1[10];
    char    guid[16];
};

struct SHITEM_CONTROL_PANEL_CATEGORY {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint32  signature;
    uint32  category;
};

struct SHITEM_CDBURN {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint32  signature;
    uint32  unk1;
    uint32  unk2;
};

struct SHITEM_GAME_FOLDER {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint32  signature;
    char    identifier[16];
    uint64  unk1;
};

struct SHITEM_CONTROL_PANEL_CPL_FILE {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint32  signature;
    uint32  unk1;
    uint32  unk2;
    uint32  unk3;
    uint16  name_offset;
    uint16  comments_offset;
    wchar   cpl_path[];
    wchar   name[];
    wchar   comments[];
};

struct SHITEM_MTP_PROPERTY {
    char    format_identifier[16];
    uint32  value_identifier;
    uint32  value_type;
};

struct SHITEM_MTP_FILE_ENTRY {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint16  data_size;
    uint32  data_signature;
    uint32  unk1;
    uint16  unk2;
    uint16  unk3;
    uint16  unk4;
    uint16  unk5;
    uint32  unk6;
    uint64  modification_time;
    uint64  creation_time;
    char    content_type_folder[16];
    uint32  unk7;
    uint32  folder_name_size_1;
    uint32  folder_name_size_2;
    uint32  folder_identifier_size;
    wchar   folder_name_1[folder_name_size_1];
    wchar   folder_name_2[folder_name_size_2];
    uint32  unk8;
    char    class_identifier[16];
    uint32  num_properties;
};

struct SHITEM_MTP_VOLUME_GUID {
    wchar   guid[39];
};

struct SHITEM_MTP_VOLUME {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint16  data_size;
    uint32  data_signature;
    uint32  unk1;
    uint16  unk2;
    uint16  unk3;
    uint16  unk4;
    uint16  unk5;
    uint32  unk6;
    uint64  unk7;
    uint32  unk8;
    uint32  name_size;
    uint32  identifier_size;
    uint32  filesystem_size;
    uint32  num_guid;
    wchar   name[name_size];
    wchar   identifier[identifier_size];
    wchar   filesystem[filesystem_size];
    SHITEM_MTP_VOLUME_GUID     guids[num_guid];
    uint32  unk9;
    char    class_identifier[16];
    uint32  num_properties;
};

struct SHITEM_USERS_PROPERTY_VIEW {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint16  data_size;
    uint32  data_signature;
    uint16  property_store_size;
    uint16  identifier_size;
    char    identifier[identifier_size];
    char    property_store[property_store_size];
    uint16  unk1;
};

struct SHITEM_UNKNOWN_0x74 {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint16  data_size;
    uint32  data_signature;
    uint16  subitem_size;
};

struct SHITEM_UNKNOWN_0x74_SUBITEM {
    uint8   type;
    uint8   unk1;
    uint32  file_size;
    uint32  modification_time;
    uint16  file_attribute_flags;
    char    primary_name[];
};

struct SHITEM_DELEGATE {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint16  data_size;
    char    data[data_size - 2];
    char    delegate_identifier[16];
    char    shell_identifier[16];
};

struct EXTENSION_BLOCK_HEADER {
    uint16  size;
    uint16  version;
    uint32  signature;
};
"""
c_bag = cstruct.cstruct()
c_bag.load(bag_def)

DELEGATE_ITEM_IDENTIFIER = b"\x74\x1a\x59\x5e\x96\xdf\xd3\x48\x8d\x67\x17\x33\xbc\xee\x28\xba"


ShellBagRecord = create_extended_descriptor([RegistryRecordDescriptorExtension, UserRecordDescriptorExtension])(
    "windows/shellbag",
    [
        ("uri", "path"),
        ("datetime", "creation_time"),
        ("datetime", "modification_time"),
        ("datetime", "access_time"),
        ("datetime", "regf_modification_time"),
    ],
)


class ShellBagsPlugin(Plugin):
    """Windows Shellbags plugin.

    Resources:
        https://github.com/libyal/libfwsi
    """

    KEYS = [
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Shell",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\ShellNoRoam",
        "HKEY_CURRENT_USER\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell",
        "HKEY_CURRENT_USER\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\ShellNoRoam",
        "HKEY_CURRENT_USER\\Software\\Classes\\Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\Shell",
        "HKEY_CURRENT_USER\\Software\\Classes\\Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\ShellNoRoam",
        "HKEY_CURRENT_USER\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
    ]

    def __init__(self, target):
        super().__init__(target)
        self.bagkeys = list(self.target.registry.keys(self.KEYS))

    def check_compatible(self):
        if not len(self.bagkeys) > 0:
            raise UnsupportedPluginError("No shellbags found")

    @export(record=ShellBagRecord)
    def shellbags(self):
        """Return Windows Shellbags.

        Shellbags are registry keys to improve user experience when using Windows Explorer. It stores information about
        for example file/folder creation time and access time.

        Sources:
            - https://www.hackingarticles.in/forensic-investigation-shellbags/
        """
        for regkey in self.bagkeys:
            try:
                bagsmru = regkey.subkey("BagMRU")

                for r in self._walk_bags(bagsmru, None):
                    yield r
            except RegistryKeyNotFoundError:
                continue
            except Exception:  # noqa
                self.target.log.exception("Exception while parsing shellbags")
                continue

    def _walk_bags(self, key, path_prefix):
        path_prefix = [] if path_prefix is None else [path_prefix]

        user = self.target.registry.get_user(key)

        for reg_val in key.values():
            name, value = reg_val.name, reg_val.value
            if not name.isdigit():
                continue
            path = None

            for item in parse_shell_item_list(value):
                path = "\\".join(path_prefix + [item.name])
                yield ShellBagRecord(
                    path=path,
                    creation_time=item.creation_time,
                    modification_time=item.modification_time,
                    access_time=item.access_time,
                    regf_modification_time=key.ts,
                    _target=self.target,
                    _user=user,
                    _key=key,
                )

            for r in self._walk_bags(key.subkey(name), path):
                yield r


def parse_shell_item_list(buf):
    offset = 0
    end = len(buf)
    list_buf = memoryview(buf)

    parent = None
    while offset < end:
        size = c_bag.uint16(list_buf[offset : offset + 2])

        if size == 0:
            break

        item_buf = list_buf[offset : offset + size]

        entry = None
        if size >= 8:
            signature = c_bag.uint32(item_buf[4:8])
            if signature == 0x39DE2184:
                entry = CONTROL_PANEL_CATEGORY
            elif signature == 0x4D677541:
                entry = CDBURN
            elif signature == 0x49534647:
                entry = GAME_FOLDER
            elif signature == 0xFFFFFF38:
                entry = CONTROL_PANEL_CPL_FILE

        if size >= 10 and not entry:
            signature = c_bag.uint32(item_buf[6:10])
            if signature == 0x07192006:
                entry = MTP_FILE_ENTRY
            elif signature == 0x10312005:
                entry = MTP_VOLUME
            elif signature in (0x10141981, 0x23A3DFD5, 0x23FEBBEE, 0x3B93AFBB, 0xBEEBEE00):
                entry = USERS_PROPERTY_VIEW
            elif signature == 0x46534643:
                entry = UNKNOWN_0x74

        if size >= 38 and not entry:
            if item_buf[size - 32 : size] == DELEGATE_ITEM_IDENTIFIER:
                entry = DELEGATE

        if size >= 3 and not entry:
            class_type = item_buf[2]
            mask_type = class_type & 0x70

            if mask_type == 0x00:
                if class_type == 0x00:
                    entry = UNKNOWN0
                elif class_type == 0x01:
                    entry = UNKNOWN1

            elif mask_type == 0x10:
                if class_type == 0x1F:
                    entry = ROOT_FOLDER

            elif mask_type == 0x20:
                if class_type in (0x23, 0x25, 0x29, 0x2A, 0x2E, 0x2F):
                    entry = VOLUME

            elif mask_type == 0x30:
                if class_type in (0x30, 0x31, 0x32, 0x35, 0x36, 0xB1):
                    entry = FILE_ENTRY

            elif mask_type == 0x40:
                if class_type in (0x41, 0x42, 0x46, 0x47, 0x4C, 0xC3):
                    entry = NETWORK

            elif mask_type == 0x50:
                if class_type == 0x52:
                    entry = COMPRESSED_FOLDER

            elif mask_type == 0x60:
                if class_type == 0x61:
                    entry = URI

            elif mask_type == 0x70:
                if class_type == 0x71:
                    entry = CONTROL_PANEL
            else:
                if not entry:
                    log.debug("No supported shell item found for size 0x%04x and type 0x%02x", size, class_type)
                    entry = UNKNOWN

        if not entry:
            log.debug("No supported shell item found for size 0x%04x", size)
            entry = UNKNOWN

        entry = entry(item_buf)
        entry.parent = parent

        first_extension_block_offset = c_bag.uint16(item_buf[-2:])
        if 4 <= first_extension_block_offset < size - 2:
            extension_offset = first_extension_block_offset
            while extension_offset < size - 2:
                extension_size = c_bag.uint16(item_buf[extension_offset : extension_offset + 2])

                if extension_size == 0:
                    break

                if extension_size > size - extension_offset:
                    log.debug(
                        "Extension size exceeds item size: 0x%04x > 0x%04x - 0x%04x",
                        extension_size,
                        size,
                        extension_offset,
                    )
                    break  # Extension size too large

                extension_buf = item_buf[extension_offset : extension_offset + extension_size]
                extension_signature = c_bag.uint32(extension_buf[4:8])

                ext = None

                if extension_signature >> 16 != 0xBEEF:
                    log.debug("Got unsupported extension signature 0x%08x from item %r", extension_signature, entry)
                    pass  # Unsupported

                elif extension_signature == 0xBEEF0000:
                    pass

                elif extension_signature == 0xBEEF0001:
                    pass

                elif extension_signature == 0xBEEF0003:
                    ext = EXTENSION_BLOCK_BEEF0004

                elif extension_signature == 0xBEEF0004:
                    ext = EXTENSION_BLOCK_BEEF0004

                elif extension_signature == 0xBEEF0005:
                    ext = EXTENSION_BLOCK_BEEF0005

                elif extension_signature == 0xBEEF0006:
                    pass

                elif extension_signature == 0xBEEF000A:
                    pass

                elif extension_signature == 0xBEEF0013:
                    pass

                elif extension_signature == 0xBEEF0014:
                    pass

                elif extension_signature == 0xBEEF0019:
                    pass

                elif extension_signature == 0xBEEF0025:
                    pass

                elif extension_signature == 0xBEEF0026:
                    pass

                else:
                    log.debug(
                        "Got unsupported beef extension signature 0x%08x from item %r", extension_signature, entry
                    )
                    pass

                if ext is None:
                    ext = EXTENSION_BLOCK
                    log.debug("Unimplemented extension signature 0x%08x from item %r", extension_signature, entry)

                ext = ext(extension_buf)

                entry.extensions.append(ext)
                extension_offset += extension_size

        parent = entry
        yield entry

        offset += size


class SHITEM:
    STRUCT = None

    def __init__(self, buf):
        self.buf = buf
        self.fh = io.BytesIO(buf)
        self.item = self.STRUCT(self.fh) if self.STRUCT is not None else None
        self.size = self.item.size if self.item else len(self.buf)
        self.type = self.item.type if self.item else None
        self.parent = None
        self.extensions = []

    @property
    def name(self):
        return f"<SHITEM 0x{self.size:x}>"

    @property
    def creation_time(self):
        return None

    @property
    def modification_time(self):
        return None

    @property
    def access_time(self):
        return None

    @property
    def file_size(self):
        return None

    @property
    def file_reference(self):
        return None

    def extension(self, cls):
        for ext in self.extensions:
            if isinstance(ext, cls):
                return ext
        return None

    def __repr__(self):
        return f"<{self.__class__.__name__}>"


class UNKNOWN(SHITEM):
    @property
    def name(self):
        type_number = hex(self.type) if self.type else self.type
        return f"<UNKNOWN size=0x{self.size:04x} type={type_number}>"


class UNKNOWN0(SHITEM):
    STRUCT = c_bag.SHITEM_UNKNOWN0

    def __init__(self, fh):
        super().__init__(fh)
        self.guid = None

        if self.item.size == 0x20:
            self.guid = uuid.UUID(bytes_le=fh.read(16))

    @property
    def name(self):
        if self.guid:
            GUID_name = shell_folder_ids.DESCRIPTIONS.get(str(self.guid))
            return GUID_name or f"<UNKNOWN0: {{{self.guid}}}>"
        else:
            return f"<UNKNOWN0 0x{self.size:x}>"


class UNKNOWN1(SHITEM):
    STRUCT = c_bag.SHITEM_UNKNOWN1

    @property
    def name(self):
        return f"<UNKNOWN1 0x{self.size:x}>"


class ROOT_FOLDER(SHITEM):  # noqa
    STRUCT = c_bag.SHITEM_ROOT_FOLDER

    def __init__(self, fh):
        super().__init__(fh)
        self.guid = uuid.UUID(bytes_le=self.item.guid)
        self.extension = None

        if self.item.size > 20:
            self.extension = None

    @property
    def name(self):
        GUID_name = shell_folder_ids.DESCRIPTIONS.get(str(self.guid))
        return GUID_name or f"{{{self.item.folder_id.name}: {self.guid}}}"


class VOLUME(SHITEM):
    STRUCT = c_bag.SHITEM_VOLUME

    def __init__(self, buf):
        super().__init__(buf)
        self.volume_name = None
        self.identifier = None
        if self.type == 0x2E:
            self.identifier = uuid.UUID(bytes_le=buf[4:20].tobytes())
        else:
            self.volume_name = self.fh.read(20).rstrip(b"\x00").decode()
            if self.size >= 41:
                self.identifier = uuid.UUID(bytes_le=buf[25:41].tobytes())

    @property
    def name(self):
        if self.volume_name:
            return self.volume_name
        if self.identifier:
            GUID_name = shell_folder_ids.DESCRIPTIONS.get(str(self.identifier))
            return GUID_name or f"{{{self.identifier}}}"
        return f"<VOLUME 0x{self.type:02x}>"


class FILE_ENTRY(SHITEM):  # noqa
    STRUCT = c_bag.SHITEM_FILE_ENTRY

    def __init__(self, buf):
        super().__init__(buf)

        has_swn1 = False
        if buf[-30:] == b"S.W.N.1":
            has_swn1 = True

        if has_swn1 or self.type & 0x4:  # FILE_ENTRY_FLAG_IS_UNICODE
            self.primary_name = c_bag.wchar[None](self.fh)
            self.is_unicode = True
        else:
            self.primary_name = c_bag.char[None](self.fh).decode()
            self.is_unicode = False

        if self.fh.tell() % 2:
            self.fh.read(1)

        extension_size = c_bag.uint16(self.fh)
        self.fh.seek(-2, io.SEEK_CUR)

        self.is_pre_xp = False
        if not has_swn1 and ((self.size - self.fh.tell() < 2) or extension_size > self.size):
            self.is_pre_xp = True
            if self.is_unicode:
                self.secondary_name = c_bag.wchar[None](self.fh)
            else:
                self.secondary_name = c_bag.char[None](self.fh).decode()

    @property
    def name(self):
        ext = self.extension(EXTENSION_BLOCK_BEEF0004)
        if ext and ext.long_name:
            return ext.long_name
        return self.primary_name

    @property
    def modification_time(self):
        ts = self.item.modification_time
        if ts > 0:
            return dostimestamp(ts, swap=True)
        return None


class NETWORK(SHITEM):
    STRUCT = c_bag.SHITEM_NETWORK

    def __init__(self, buf):
        super().__init__(buf)
        self.description = None
        self.comments = None

        if self.item.flags & 0x80:
            self.description = c_bag.char[None](self.fh)

        if self.item.flags & 0x40:
            self.comments = c_bag.char[None](self.fh)

    @property
    def name(self):
        return self.item.location.decode()


class COMPRESSED_FOLDER(SHITEM):  # noqa
    STRUCT = c_bag.SHITEM_COMPRESSED_FOLDER

    @property
    def name(self):
        return "<COMPRESSED_FOLDER>"


class URI(SHITEM):
    STRUCT = c_bag.SHITEM_URI

    def __init__(self, buf):
        super().__init__(buf)
        self.uri = None
        if self.item.data_size < self.size - 6:
            self.data = self.fh.read(self.item.data_size - 2)
            if self.item.flags & 0x80:
                self.uri = c_bag.wchar[None](self.fh)
            else:
                self.uri = c_bag.char[None](self.fh).decode()

    @property
    def name(self):
        return self.uri or "<URI>"


class CONTROL_PANEL(SHITEM):  # noqa
    STRUCT = c_bag.SHITEM_CONTROL_PANEL

    def __init__(self, buf):
        super().__init__(buf)
        self.guid = uuid.UUID(bytes_le=self.item.guid)

    @property
    def name(self):
        GUID_name = shell_folder_ids.DESCRIPTIONS.get(str(self.guid))
        return GUID_name or f"<CONTROL_PANEL {self.guid}>"


class CONTROL_PANEL_CATEGORY(SHITEM):  # noqa
    STRUCT = c_bag.SHITEM_CONTROL_PANEL_CATEGORY
    CATEGORIES = {
        0: "All Control Panel Items",
        1: "Appearance and Personalization",
        2: "Hardware and Sound",
        3: "Network and Internet",
        4: "Sounds, Speech, and Audio Devices",
        5: "System and Security",
        6: "Clock, Language, and Region",
        7: "Ease of Access",
        8: "Programs",
        9: "User Accounts",
        10: "Security Center",
        11: "Mobile PC",
    }

    @property
    def name(self):
        categ_str = self.CATEGORIES.get(self.item.category)
        if categ_str:
            return categ_str
        return f"<CONTROL_PANEL_CATEGORY 0x{self.item.unk1:08x}>"


class CDBURN(SHITEM):
    STRUCT = c_bag.SHITEM_CDBURN

    @property
    def name(self):
        return "<CDBURN>"


class GAME_FOLDER(SHITEM):  # noqa
    STRUCT = c_bag.SHITEM_GAME_FOLDER

    def __init__(self, buf):
        super().__init__(buf)
        self.guid = uuid.UUID(bytes_le=self.item.identifier)

    @property
    def name(self):
        return f"<GAME_FOLDER {{{self.guid}}}>"


class CONTROL_PANEL_CPL_FILE(SHITEM):  # noqa
    STRUCT = c_bag.SHITEM_CONTROL_PANEL_CPL_FILE

    @property
    def name(self):
        return f"<CONTROL_PANEL_CPL_FILE path={self.item.cpl_path} name={self.item.name} comments={self.item.comments}>"


class MTP_FILE_ENTRY(SHITEM):  # noqa
    STRUCT = c_bag.SHITEM_MTP_FILE_ENTRY

    @property
    def name(self):
        return "<MTP_FILE_ENTRY>"

    @property
    def creation_time(self):
        return self.item.creation_time

    @property
    def modification_time(self):
        return self.item.modification_time


class MTP_VOLUME(SHITEM):  # noqa
    STRUCT = c_bag.SHITEM_MTP_FILE_ENTRY

    @property
    def name(self):
        return "<MTP_VOLUME>"


class USERS_PROPERTY_VIEW(SHITEM):  # noqa
    STRUCT = c_bag.SHITEM_USERS_PROPERTY_VIEW

    def __init__(self, buf):
        super().__init__(buf)
        self.guid = None
        self.identifier = self.item.data_signature

        if self.item.identifier_size == 16:
            self.guid = uuid.UUID(bytes_le=self.item.identifier)

    @property
    def name(self):
        # As we don't know how to handle identifier_size other than 16 bytes, we fall back to data_signature
        property_view = self.guid or self.identifier
        return f"<USERS_PROPERTY_VIEW {{{property_view}}}>"


class UNKNOWN_0x74(SHITEM):  # noqa
    STRUCT = c_bag.SHITEM_UNKNOWN_0x74

    def __init__(self, buf):
        super().__init__(buf)
        self.subitem = None
        if self.item.subitem_size >= 16:
            self.subitem = c_bag.SHITEM_UNKNOWN_0x74_SUBITEM(self.fh)

    @property
    def name(self):
        return self.subitem.primary_name.decode() if self.subitem else "<UNKNOWN_0x74>"

    @property
    def modification_time(self):
        if self.subitem.modification_time > 0:
            return dostimestamp(self.subitem.modification_time, swap=True) if self.subitem else None
        return None


class DELEGATE(SHITEM):
    STRUCT = c_bag.SHITEM_DELEGATE

    def __init__(self, buf):
        super().__init__(buf)
        self.delegate_identifier = uuid.UUID(bytes_le=self.item.delegate_identifier)
        self.shell_identifier = uuid.UUID(bytes_le=self.item.shell_identifier)

    @property
    def name(self):
        GUID_name = shell_folder_ids.DESCRIPTIONS.get(str(self.shell_identifier))
        return GUID_name if GUID_name else f"{{{self.shell_identifier}}}"


class EXTENSION_BLOCK:  # noqa
    def __init__(self, buf):
        self.buf = buf
        self.fh = io.BytesIO(buf)
        self.header = c_bag.EXTENSION_BLOCK_HEADER(self.fh)

    @property
    def size(self):
        return self.header.size

    @property
    def data_size(self):
        return self.size - 8  # minus header

    @property
    def version(self):
        return self.header.version

    @property
    def signature(self):
        return self.header.signature

    def __repr__(self):
        return f"<EXTENSION_BLOCK size=0x{self.size:04x} version=0x{self.version:04x} signature=0x{self.signature:08x}>"


class EXTENSION_BLOCK_BEEF0004(EXTENSION_BLOCK):  # noqa
    def __init__(self, buf):
        super().__init__(buf)
        fh = self.fh
        version = self.version
        self.creation_time = c_bag.uint32(fh)
        self.last_accessed = c_bag.uint32(fh)
        self.identifier = c_bag.uint16(fh)
        self.file_reference = None
        self.long_name = None
        self.localized_name = None
        # Note that the c_bag.uintXX() etc. statements advance the pointer into
        # the filebuffer, so the order of the if statements is important here.
        if version >= 7:
            c_bag.uint16(fh)
            self.file_reference = c_bag.uint64(fh)
            c_bag.uint64(fh)
        if version >= 3:
            long_len = c_bag.uint16(fh)
        if version >= 9:
            c_bag.uint32(fh)
        if version >= 8:
            c_bag.uint32(fh)
        if version >= 3:
            self.long_name = c_bag.wchar[None](fh)
        if 3 <= version < 7 and long_len > 0:
            self.localized_name = c_bag.char[long_len](fh)
        if version >= 7 and long_len > 0:
            self.localized_name = c_bag.wchar[long_len](fh)


class EXTENSION_BLOCK_BEEF0005(EXTENSION_BLOCK):  # noqa
    def __init__(self, buf):
        super().__init__(buf)
        c_bag.char[16](self.fh)  # GUID?
        self.shell_items = self.fh.read(self.data_size - 18)
