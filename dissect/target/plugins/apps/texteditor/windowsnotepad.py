import zlib
from typing import BinaryIO, Iterator

from dissect import cstruct

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.texteditor.texteditor import (
    GENERIC_TAB_CONTENTS_RECORD_FIELDS,
    TexteditorPlugin,
)

c_def = """
struct multi_block_entry {
    uint16    offset;
    uleb128   len;
    wchar     data[len];
    char      crc32[4];
};

struct single_block_entry {
    uint16    offset;
    uleb128   len;
    wchar     data[len];
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
    uleb128                     fsize1;
    uleb128                     fsize2;
    char                        header_end[2];    // \x01\x00

    // Data can be stored in two says:
    //  1. A single, contiguous block of data that holds all the data
    //     In this case, the header is included in the single CRC32 checksum present at the end of the block
    //  2. Multiple blocks of data that, when combined, hold all the data
    //     In this case, the header has a separate CRC32 value stored at the end of the header
    // The following bitmask operations basically check whether fsize1 is nonzero (boolean check) and depending
    // on the outcome, parse 0 or 1 (so basically, parse or not parse) structs.
    header_crc                  header_crc[((fsize1 | -fsize1) >> 31) ^ 1]; // Optional, only if fsize1 == 0
    single_block_entry          single_block_entry[((fsize1 | (~fsize1 + 1)) >> 31) & 1];  // Optional, only if fsize1 > 0  # noqa: E501


    multi_block_entry           multi_block_entries[EOF];  // Optional. If a single_block_entry is present
                                                           // this will already be at EOF, so it won't do anything.
                                                           // Otherwise, it will parse the individual blocks.
};
"""
TextEditorTabRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "texteditor/windowsnotepad/tab", GENERIC_TAB_CONTENTS_RECORD_FIELDS
)

c_windowstab = cstruct.cstruct()
c_windowstab.load(c_def)


def _calc_crc32(data: bytes) -> bytes:
    """Perform a CRC32 checksum on the data and return it as bytes"""
    return zlib.crc32(data).to_bytes(length=4, byteorder="big")


class WindowsNotepadPlugin(TexteditorPlugin):
    """Windows notepad tab content plugin."""

    __namespace__ = "windowsnotepad"

    GLOB = "AppData/Local/Packages/Microsoft.WindowsNotepad_*/LocalState/TabState/*.bin"

    def __init__(self, target):
        super().__init__(target)
        self.users_tabs = []

        for user_details in self.target.user_details.all_with_home():
            for tab_file in user_details.home_path.glob(self.GLOB):
                if tab_file.name.endswith(".1.bin") or tab_file.name.endswith(".0.bin"):
                    continue

                self.users_tabs.append(tab_file)

    def check_compatible(self) -> None:
        if not self.users_tabs:
            raise UnsupportedPluginError("No Windows Notepad temporary tab files found")

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
            size = data_entry.len

            # The header (minus the magic) plus all data (exluding the CRC32 at the end) is included in the checksum
            actual_crc32 = _calc_crc32(tab.dumps()[3:-4])

            if data_entry.crc32 != actual_crc32:
                self.target.log.warning(
                    "CRC32 mismatch in single-block file: %s " "expected=%s, actual=%s",
                    file.name,
                    data_entry.crc32.hex(),
                    actual_crc32.hex(),
                )

            text = data_entry.data

        else:
            # Reconstruct the text of the multi_block_entry variant
            # CRC32 is calculated based on the entire header, up to the point where the CRC32 value is stored
            defined_header_crc32 = tab.header_crc[0].crc32
            actual_header_crc32 = _calc_crc32(tab.dumps()[3 : tab.dumps().index(defined_header_crc32)])
            if defined_header_crc32 != actual_header_crc32:
                self.target.log.warning(
                    "CRC32 mismatch in header of multi-block file: %s " "expected=%s, actual=%s",
                    file.name,
                    defined_header_crc32.hex(),
                    actual_header_crc32.hex(),
                )

            # Since we don't know the size of the file up front, and offsets don't necessarily have to be in order,
            # a list is used to easily insert text at offsets
            text = []
            size = 0

            for data_entry in tab.multi_block_entries:
                # If there is no data to be added, skip. This may happen sometimes.
                if data_entry.len <= 0:
                    continue

                size += data_entry.len
                # Check the CRC32 checksum for this block
                actual_crc32 = _calc_crc32(data_entry.dumps()[:-4])
                if data_entry.crc32 != actual_crc32:
                    self.target.log.warning(
                        "CRC32 mismatch in multi-block file: %s " "expected=%s, actual=%s",
                        file.name,
                        data_entry.crc32.hex(),
                        actual_crc32.hex(),
                    )

                # Extend the list if required. All characters need to fit in the list.
                while data_entry.offset + data_entry.len > len(text):
                    text.append("\x00")

                # Place the text at the correct offset. UTF16-LE consumes two bytes for one character.
                for idx in range(data_entry.len):
                    text[data_entry.offset + idx] = data_entry.data[(2 * idx) : (2 * idx) + 2]

            # Join all the characters to reconstruct the original text
            text = "".join(text)

        return TextEditorTabRecord(content=text, content_length=size, path=file)

    @export(record=TextEditorTabRecord)
    def tabs(self) -> Iterator[TextEditorTabRecord]:
        """Return contents from Windows 11 temporary Notepad tabs.

        Yields TextEditorTabRecord with the following fields:
            contents (string): The contents of the tab.
            content_length (int): The length of the tab content.
            path (path): The path the content originates from.
        """
        for file in self.users_tabs:
            yield self._process_tab_file(file)
