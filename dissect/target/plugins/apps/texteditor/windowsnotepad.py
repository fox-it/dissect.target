from __future__ import annotations

import logging
import zlib
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
from dissect.target.plugin import arg, export
from dissect.target.plugins.apps.texteditor.texteditor import (
    GENERIC_TAB_CONTENTS_RECORD_FIELDS,
    TexteditorPlugin,
)

# Thanks to @Nordgaren, @daddycocoaman, @JustArion and @ogmini for their suggestions and feedback in the PR
# thread. This really helped to figure out the last missing bits and pieces
# required for recovering text from these files.

c_def = """
struct file_header {
    char        magic[2]; // NP
    uleb128     updateNumber; // increases on every settings update when fileType=9, 
                              // doesn't seem to change on fileType 0 or 1
    uleb128     fileType; // 0 if unsaved, 1 if saved, 9 if contains settings?
}

struct tab_header_saved {
    uleb128     filePathLength;
    wchar       filePath[filePathLength];
    uleb128     fileSize; // likely similar to fixedSizeBlockLength
    uleb128     encoding;
    uleb128     carriageReturnType;
    uleb128     timestamp; // Windows Filetime format (not unix timestamp)
    char        sha256[32];
    char        unk0;
    char        unk1;
    uleb128     fixedSizeBlockLength;
    uleb128     fixedSizeBlockLengthDuplicate;
    uint8       wordWrap; // 1 if wordwrap enabled, 0 if disabled
    uint8       rightToLeft;
    uint8       showUnicode;
    uint8       optionsVersion;
};

struct tab_header_unsaved {
    char        unk0;
    uleb128     fixedSizeBlockLength; // will always be 00 when unsaved because size is not yet known
    uleb128     fixedSizeBlockLengthDuplicate; // will always be 00 when unsaved because size is not yet known
    uint8       wordWrap; // 1 if wordwrap enabled, 0 if disabled
    uint8       rightToLeft;
    uint8       showUnicode;
    uint8       optionsVersion;
};

struct tab_header_crc32_stub {
    char        unk1;
    char        unk2;
    char        crc32[4];
};

struct fixed_size_data_block {
    uleb128     nAdded;
    wchar       data[nAdded];
    uint8       hasRemainingVariableDataBlocks; // indicates whether after this single-data block more data will follow
    char        crc32[4];
};

struct variable_size_data_block {
    uleb128     offset;
    uleb128     nDeleted;
    uleb128     nAdded;
    wchar       data[nAdded];
    char        crc32[4];
};

struct options_v1 {
    uleb128     unk;
};

struct options_v2 {
    uleb128     unk1; // likely autocorrect or spellcheck
    uleb128     unk2; // likely autocorrect or spellcheck
};
"""

c_windowstab = cstruct()
c_windowstab.load(c_def)

WindowsNotepadTabRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "texteditor/windowsnotepad/tab", GENERIC_TAB_CONTENTS_RECORD_FIELDS
)

WindowsNotepadTabContentRecord = create_extended_descriptor([])(
    "texteditor/windowsnotepad/tab_content", GENERIC_TAB_CONTENTS_RECORD_FIELDS
)


def _calc_crc32(data: bytes) -> bytes:
    """Perform a CRC32 checksum on the data and return it as bytes."""
    return zlib.crc32(data).to_bytes(length=4, byteorder="big")


class WindowsNotepadTabContent:
    """Windows notepad tab parser"""

    def __new__(cls, file: TargetPath, include_deleted_content=False) -> WindowsNotepadTabContentRecord:
        return cls._process_tab_file(file, include_deleted_content)

    @staticmethod
    def _process_tab_file(file: TargetPath, include_deleted_content: bool) -> WindowsNotepadTabContentRecord:
        """Parse a binary tab file and reconstruct the contents.

        Args:
            file: The binary file on disk that needs to be parsed.

        Returns:
            A TextEditorTabRecord containing information that is in the tab.
        """
        with file.open("rb") as fh:
            # Header is the same for all types
            file_header = c_windowstab.file_header(fh)

            # Tabs can be saved to a file with a filename on disk, or unsaved (kept in the TabState folder).
            # Depending on the file's saved state, different header fields are present
            tab_header = (
                c_windowstab.tab_header_saved(fh)
                if file_header.fileType == 0x01  # 0x00 is unsaved, 0x01 is saved, 0x09 is settings?
                else c_windowstab.tab_header_unsaved(fh)
            )

            # There appears to be a optionsVersion field that specifies the options that are passed.
            # At the moment of writing, it is not sure whether this specifies a version or a number of bytes
            # that is parsed, so just going with the 'optionsVersion' type for now.
            # We don't use the options, but since they are required for the CRC32 checksum
            # we store the byte representation
            if tab_header.optionsVersion == 0:
                # No options specified
                options = b""
            elif tab_header.optionsVersion == 1:
                options = c_windowstab.options_v1(fh).dumps()
            elif tab_header.optionsVersion == 2:
                options = c_windowstab.options_v2(fh).dumps()
            else:
                # Raise an error, since we don't know how many bytes future optionVersions will occupy.
                # Now knowing how many bytes to parse can mess up the alignment and structs.
                raise Exception("Unknown option version")

            # If the file is not saved to disk and no fixedSizeBlockLength is present, an extra checksum stub
            # is present. So parse that first
            if file_header.fileType == 0 and tab_header.fixedSizeBlockLength == 0:
                # Two unknown bytes before the CRC32
                tab_header_crc32_stub = c_windowstab.tab_header_crc32_stub(fh)

                # Calculate CRC32 of the header and check if it matches
                actual_header_crc32 = _calc_crc32(
                    file_header.dumps()[3:] + tab_header.dumps() + options + tab_header_crc32_stub.dumps()[:-4]
                )
                if tab_header_crc32_stub.crc32 != actual_header_crc32:
                    logging.warning(
                        "CRC32 mismatch in header of file: %s (expected=%s, actual=%s)",
                        file.name,
                        tab_header_crc32_stub.crc32.hex(),
                        actual_header_crc32.hex(),
                    )

            # Used to store the final content
            content = ""

            # After a fixed_size_data_block, some more variable_size_data_blocks can be present. This boolean
            # keeps track of whether more data is still present.
            has_remaining_data = False

            # In the case that a fixedSizeDataBlock is present, this value is set to a nonzero value
            if tab_header.fixedSizeBlockLength > 0:
                # So we parse the fixed size data block
                data_entry = c_windowstab.fixed_size_data_block(fh)

                # The header (minus the magic) plus all data is included in the checksum
                actual_crc32 = _calc_crc32(
                    file_header.dumps()[3:] + tab_header.dumps() + options + data_entry.dumps()[:-4]
                )

                if data_entry.crc32 != actual_crc32:
                    logging.warning(
                        "CRC32 mismatch in single-block file: %s (expected=%s, actual=%s)",
                        file.name,
                        data_entry.crc32.hex(),
                        actual_crc32.hex(),
                    )

                # Add the content of the fixed size data block to the tab content
                content += data_entry.data

                # The hasRemainingVariableDataBlocks indicates whether more data will follow after this single block
                if data_entry.hasRemainingVariableDataBlocks == 1:
                    has_remaining_data = True

            # If fixedSizeBlockLength in the header has a value of zero, this means that the entire file consists of
            # variable-length blocks. Furthermore, if there is any remaining data after the
            # first fixed size blocks, also continue we also want to continue parsing
            if tab_header.fixedSizeBlockLength == 0 or has_remaining_data:
                # Here, data is stored in variable-length blocks. This happens, for example, when several
                # additions and deletions of characters have been recorded and these changes have not been 'flushed'

                # Since we don't know the size of the file up front, and offsets don't necessarily have to be in order,
                # a list is used to easily insert text at offsets
                text = []

                # Used to store the deleted content, if available and requested
                deleted_content = ""

                while True:
                    # Unfortunately, there is no way of determining how many blocks there are. So just try to parse
                    # until we reach EOF, after which we stop.
                    try:
                        data_entry = c_windowstab.variable_size_data_block(fh)
                    except EOFError:
                        break

                    # Either the nAdded is nonzero, or the nDeleted
                    if data_entry.nAdded > 0:
                        # Check the CRC32 checksum for this block
                        actual_crc32 = _calc_crc32(data_entry.dumps()[:-4])
                        if data_entry.crc32 != actual_crc32:
                            logging.warning(
                                "CRC32 mismatch in multi-block file: %s (expected=%s, actual=%s)",
                                file.name,
                                data_entry.crc32.hex(),
                                actual_crc32.hex(),
                            )

                        # Insert the text at the correct offset.
                        for idx in range(data_entry.nAdded):
                            text.insert(data_entry.offset + idx, data_entry.data[idx])

                    elif data_entry.nDeleted > 0:
                        # Create a new slice. Include everything up to the offset,
                        # plus everything after the nDeleted following bytes
                        if include_deleted_content:
                            deleted_content += "".join(
                                text[data_entry.offset : data_entry.offset + data_entry.nDeleted]
                            )
                        text = text[: data_entry.offset] + text[data_entry.offset + data_entry.nDeleted :]

                # Join all the characters to reconstruct the original text within the variable-length data blocks
                text = "".join(text)

                # Add the deleted content, if specified
                if include_deleted_content:
                    text += " --- DELETED-CONTENT: "
                    text += deleted_content

                # Finally, add the reconstructed text to the tab content
                content += text

        return WindowsNotepadTabContentRecord(content=content, path=file)


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

    @arg(
        "--include-deleted-content",
        type=bool,
        default=False,
        required=False,
        help="Include deleted but recoverable content.",
    )
    @export(record=WindowsNotepadTabRecord)
    def tabs(self, include_deleted_content) -> Iterator[WindowsNotepadTabRecord]:
        """Return contents from Windows 11 temporary Notepad tabs.

        Yields TextEditorTabRecord with the following fields:
            contents (string): The contents of the tab.
            path (path): The path the content originates from.
        """
        for file, user in self.users_tabs:
            # Parse the file
            r: WindowsNotepadTabContentRecord = WindowsNotepadTabContent(file, include_deleted_content)

            # Add user- and target specific information to the content record
            yield WindowsNotepadTabRecord(content=r.content, path=r.path, _target=self.target, _user=user)
