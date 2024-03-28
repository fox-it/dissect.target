from __future__ import annotations

import zlib
from enum import IntEnum
from typing import Iterator

from dissect.cstruct import cstruct

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import (
    UnixUserRecord,
    WindowsUserRecord,
    create_extended_descriptor,
)
from dissect.target.plugin import export
from dissect.target.plugins.apps.texteditor.texteditor import (
    GENERIC_TAB_CONTENTS_RECORD_FIELDS,
    TexteditorPlugin,
)

# Thanks to @Nordgaren, @daddycocoaman, @JustArion and @ogmini for their suggestions and feedback in the PR
# thread. This really helped figuring out the last missing bits and pieces
# required for recovering text from these files.

c_def = """
struct header {
    char        magic[2]; // NP
    uint8       unk0;
    uint8       fileState; // 0 if unsaved, 1 if saved
}

struct header_saved_tab {
    uleb128     filePathLength;
    wchar       filePath[filePathLength];
    uleb128     fileSize;
    uleb128     encoding;
    uleb128     carriageReturnType;
    uleb128     timestamp; // Windows Filetime format (not unix timestamp)
    char        sha256[32];
    char        unk[6];
};

struct header_unsaved_tab {
    uint8       unk0;
    uleb128     fileSize;
    uleb128     fileSizeDuplicate;
    uint8       unk1;
    uint8       unk2;
};

struct data_block {
    uleb128     offset;
    uleb128     nDeleted;
    uleb128     nAdded;
    wchar       data[nAdded];
};
"""

c_windowstab = cstruct()
c_windowstab.load(c_def)

TextEditorTabRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "texteditor/windowsnotepad/tab", GENERIC_TAB_CONTENTS_RECORD_FIELDS
)


class FileState(IntEnum):
    Unsaved = 0x00
    Saved = 0x01


def _calc_crc32(data: bytes) -> bytes:
    """Perform a CRC32 checksum on the data and return it as bytes."""
    return zlib.crc32(data).to_bytes(length=4, byteorder="big")


class WindowsNotepadPlugin(TexteditorPlugin):
    """Windows notepad tab content plugin."""

    __namespace__ = "windowsnotepad"

    GLOB = "AppData/Local/Packages/Microsoft.WindowsNotepad_*/LocalState/TabState/*.bin"

    def __init__(self, target):
        super().__init__(target)
        self.users_tabs: list[TargetPath, UnixUserRecord | WindowsUserRecord] = []

        for user_details in self.target.user_details.all_with_home():
            for tab_file in user_details.home_path.glob(self.GLOB):
                if tab_file.name.endswith(".1.bin") or tab_file.name.endswith(".0.bin"):
                    continue

                self.users_tabs.append((tab_file, user_details.user))

    def check_compatible(self) -> None:
        if not self.users_tabs:
            raise UnsupportedPluginError("No Windows Notepad temporary tab files found")

    def _process_tab_file(self, file: TargetPath, user: UnixUserRecord | WindowsUserRecord) -> TextEditorTabRecord:
        """Parse a binary tab file and reconstruct the contents.

        Args:
            file: The binary file on disk that needs to be parsed.

        Returns:
            A TextEditorTabRecord containing information that is in the tab.
        """
        with file.open("rb") as fh:
            # Header is the same for all types
            header = c_windowstab.header(fh)

            # File can be saved, or unsaved. Depending on the filestate, different header fields are present
            # Currently, no information in the header is used in the outputted records, only the contents of the tab
            tab = (
                c_windowstab.header_saved_tab(fh)
                if header.fileState == FileState.Saved
                else c_windowstab.header_unsaved_tab(fh)
            )

            # In the case that the filesize is known up front, then this file is zet to a nonzero value
            # This means that the data is stored in one block
            if tab.fileSize != 0:
                # So we only parse one block
                data_entry = c_windowstab.data_block(fh)

                # An extra byte is appended to the single block, not yet sure where this is defined and/or used for
                extra_byte = fh.read(1)

                # The CRC32 value is appended after the extra byte in big-endian
                defined_crc32 = fh.read(4)

                # The header (minus the magic) plus all data (including the extra byte)  is included in the checksum
                actual_crc32 = _calc_crc32(header.dumps()[3:] + tab.dumps() + data_entry.dumps() + extra_byte)

                if defined_crc32 != actual_crc32:
                    self.target.log.warning(
                        "CRC32 mismatch in single-block file: %s (expected=%s, actual=%s)",
                        file.name,
                        defined_crc32.hex(),
                        actual_crc32.hex(),
                    )

                text = data_entry.data

            else:
                # Here, the fileSize is zero'ed, meaning that the size is not known up front.
                # Data may be stored in multiple, variable-length blocks. This happens, for example, when several
                # additions and deletions of characters have been recorded and these changes have not been 'flushed'

                # First, parse 4 as of yet unknown bytes
                # Likely holds some addition information about the tab (view options etc)
                unknown_bytes = fh.read(4)

                # In this multi-block variant, he header itself has a CRC32 value in big-endian as well
                defined_header_crc32 = fh.read(4)

                # Calculate CRC32 of the header and check if it matches
                actual_header_crc32 = _calc_crc32(header.dumps()[3:] + tab.dumps() + unknown_bytes)
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

                while True:
                    # Unfortunately, there is no way of determining how many blocks there are. So just try to parse
                    # until we reach EOF, after which we stop.
                    try:
                        data_entry = c_windowstab.data_block(fh)
                    except EOFError:
                        break

                    # Each block has a CRC32 value in big-endian appended to the block
                    defined_crc32 = fh.read(4)

                    # Either the nAdded is nonzero, or the nDeleted
                    if data_entry.nAdded > 0:
                        # Check the CRC32 checksum for this block
                        actual_crc32 = _calc_crc32(data_entry.dumps())
                        if defined_crc32 != actual_crc32:
                            self.target.log.warning(
                                "CRC32 mismatch in multi-block file: %s " "expected=%s, actual=%s",
                                file.name,
                                data_entry.crc32.hex(),
                                actual_crc32.hex(),
                            )

                        # Extend the list if required. All characters need to fit in the list.
                        while data_entry.offset + data_entry.nAdded > len(text):
                            text.append("\x00" * 100)

                        # Insert the text at the correct offset.
                        for idx in range(data_entry.nAdded):
                            text[data_entry.offset + idx] = data_entry.data[idx]

                    elif data_entry.nDeleted > 0:
                        # Create a new slice. Include everything up to the offset,
                        # plus everything after the nDeleted following bytes
                        text = text[: data_entry.offset] + text[data_entry.offset + data_entry.nDeleted :]

                # Join all the characters to reconstruct the original text
                text = "".join(text)

        return TextEditorTabRecord(content=text, path=file, _target=self.target, _user=user)

    @export(record=TextEditorTabRecord)
    def tabs(self) -> Iterator[TextEditorTabRecord]:
        """Return contents from Windows 11 temporary Notepad tabs.

        Yields TextEditorTabRecord with the following fields:
            contents (string): The contents of the tab.
            path (path): The path the content originates from.
        """
        for file, user in self.users_tabs:
            yield self._process_tab_file(file, user)
