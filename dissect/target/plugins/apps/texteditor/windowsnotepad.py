import zlib
from typing import BinaryIO, Iterator

from dissect import cstruct

from dissect.target.exceptions import CRCMismatchException, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.texteditor.texteditor import (
    GENERIC_TAB_CONTENTS_RECORD_FIELDS,
    TexteditorTabPlugin,
)

c_def = """
struct multi_block_entry {
    uint16    offset;
    uleb128   len;
    char      data[len * 2];
    char      crc32[4];
};

struct single_block_entry {
    uint16    offset;
    uleb128   len;
    char      data[len * 2];
    char      unk1;
    char      crc32[4];
};

struct header_crc {
    char      unk[4];
    char      crc32[4];
};

struct tab {
    char                        magic[3];         // NP\x00
    char                        header_start[2];  // \x00\x01
    uleb128                     len1;
    uleb128                     len2;
    char                        header_end[2];    // \x01\x00
    
    // Data can be stored in two says:
    //  1. A single, contiguous block of data that holds all the data
    //     In this case, the header is included in the single CRC32 checksum present at the end of the block
    //  2. Multiple blocks of data that, when combined, hold all the data
    //     In this case, the header has a separate CRC32 value stored at the end of the header
    // The following bitmask operations basically check whether len1 is nonzero (boolean check) and depending
    // on the outcome, parse 0 or 1 (so basically, parse or not parse) structs.
    header_crc                  header_crc[((len1 | -len1) >> 31) ^ 1]; // Optional, only if len1 == 0
    single_block_entry          single_block_entry[((len1 | (~len1 + 1)) >> 31) & 1];  // Optional, only if len1 > 0


    multi_block_entry           multi_block_entries[EOF];  // Optional. If a single_block_entry is present
                                                           // this will already be at EOF, so it won't do anything.
                                                           // Otherwise, it will parse the individual blocks.
};
"""

c_windowstab = cstruct.cstruct()
c_windowstab.load(c_def)


def _calc_crc32(data: bytes) -> bytes:
    """Perform a CRC32 checksum on the data and return it as bytes"""
    return zlib.crc32(data).to_bytes(length=4, byteorder="big")


class WindowsNotepadPlugin(TexteditorTabPlugin):
    """Windows notepad tab content plugin."""

    __namespace__ = "windowsnotepad"

    DIRECTORY = "AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState"
    TextEditorTabRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "texteditor/windowsnotepad/tab", GENERIC_TAB_CONTENTS_RECORD_FIELDS
    )

    def __init__(self, target):
        super().__init__(target)
        self.users_dirs = []
        for user_details in self.target.user_details.all_with_home():
            cur_dir = user_details.home_path.joinpath(self.DIRECTORY)
            if not cur_dir.exists():
                continue
            self.users_dirs.append((user_details.user, cur_dir))

    def check_compatible(self) -> None:
        if not len(self.users_dirs):
            raise UnsupportedPluginError("No tabs directories found")

    def _process_tab_file(self, file: TargetPath) -> TextEditorTabRecord:
        """
        Function that parses a binary tab file and reconstructs the contents.

        Args:
            file: The binary file on disk that needs to be parsed.

        Returns:
            A TextEditorTabRecord containing information that is in the tab.
        """
        fh: BinaryIO = file.open(mode="rb")

        tab = c_windowstab.tab(fh)

        if tab.len1 != 0:
            # Reconstruct the text of the single_block_entry variant
            data_entry = tab.single_block_entry[0]

            # The header (minus the magic) plus all data (exluding the CRC32 at the end) is included in the checksum
            actual_crc32 = _calc_crc32(tab.dumps()[3:-4])

            if data_entry.crc32 != actual_crc32:
                raise CRCMismatchException(
                    f"CRC32 mismatch in single-block file. "
                    f"expected={data_entry.crc32.hex()}, actual={actual_crc32.hex()} "
                )

            text = data_entry.data.decode("utf-16-le")

        else:
            # Reconstruct the text of the multi_block_entry variant
            # CRC32 is calculated based on the entire header, up to the point where the CRC32 value is stored
            assert tab.header_crc[0].crc32 == _calc_crc32(tab.dumps()[3 : tab.dumps().index(tab.header_crc[0].crc32)])

            # Since we don't know the size of the file up front, and offsets don't necessarily have to be in order,
            # a list is used to easily insert text at offsets
            text = ["\x00"]

            for data_entry in tab.multi_block_entries:
                # Check the CRC32 checksum for this block
                actual_crc32 = _calc_crc32(data_entry.dumps()[:-4])
                if data_entry.crc32 != actual_crc32:
                    raise CRCMismatchException(
                        f"CRC32 mismatch in single-block file. "
                        f"expected={data_entry.crc32.hex()}, actual={actual_crc32.hex()} "
                    )

                # If there is no data to be added, skip. This may happen sometimes.
                if data_entry.len <= 0:
                    continue

                # Extend the list if required. All characters need to fit in the list.
                while data_entry.offset + data_entry.len > len(text):
                    text += "\x00"

                # Place the text at the correct offset. UTF16-LE consumes two bytes for one character.
                for i in range(data_entry.len):
                    text[data_entry.offset + i] = data_entry.data[(2 * i) : (2 * i) + 2].decode("utf-16-le")

            # Join all the characters to reconstruct the original text
            text = "".join(text)

        return self.TextEditorTabRecord(content=text, content_length=len(text), filename=file.name)

    @export(record=TextEditorTabRecord)
    def tabs(self) -> Iterator[TextEditorTabRecord]:
        """Return contents from the notepad tab.

        Yields TextEditorTabRecord with the following fields:
            contents (string): The contents of the tab.
            title (string): The title of the tab.
        """
        for user, directory in self.users_dirs:
            for file in self.target.fs.path(directory).iterdir():
                if file.name.endswith(".1.bin") or file.name.endswith(".0.bin"):
                    continue

                try:
                    yield self._process_tab_file(file)
                except CRCMismatchException as e:
                    self.target.log.warning("CRC32 checksum mismatch in file: %s", file.name, exc_info=e)
                    continue
