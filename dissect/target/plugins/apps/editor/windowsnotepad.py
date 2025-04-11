from __future__ import annotations

import logging
import zlib
from typing import TYPE_CHECKING

from dissect.cstruct import cstruct
from dissect.util.ts import wintimestamp
from flow.record.fieldtypes import digest

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import (
    UnixUserRecord,
    WindowsUserRecord,
    create_extended_descriptor,
)
from dissect.target.plugin import alias, export
from dissect.target.plugins.apps.editor.editor import COMMON_EDITOR_FIELDS, EditorPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.target import Target

# Thanks to @Nordgaren, @daddycocoaman, @JustArion and @ogmini for their suggestions and feedback in the PR
# thread. This really helped to figure out the last missing bits and pieces
# required for recovering text from these files.

windowstab_def = """
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

GENERIC_TAB_CONTENTS_RECORD_FIELDS = [
    ("string", "content"),
    ("path", "path"),
    ("string", "deleted_content"),
]

WindowsNotepadUnsavedTabRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "application/editor/windowsnotepad/tab/unsaved",
    COMMON_EDITOR_FIELDS + GENERIC_TAB_CONTENTS_RECORD_FIELDS,
)

WindowsNotepadSavedTabRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "application/editor/windowsnotepad/tab/saved",
    COMMON_EDITOR_FIELDS
    + GENERIC_TAB_CONTENTS_RECORD_FIELDS
    + [
        ("digest", "digest"),
        ("path", "saved_path"),
    ],
)

c_windowstab = cstruct().load(windowstab_def)


def _calc_crc32(data: bytes) -> bytes:
    """Perform a CRC32 checksum on the data and return it as bytes."""
    return zlib.crc32(data).to_bytes(length=4, byteorder="big")


class WindowsNotepadTab:
    """Windows notepad tab content parser."""

    def __init__(self, file: TargetPath):
        self.file = file
        self.is_saved = None
        self.content = None
        self.deleted_content = None
        self._process_tab_file()

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} saved={self.is_saved} "
            f"content_size={len(self.content)} has_deleted_content={self.deleted_content is not None}>"
        )

    def _process_tab_file(self) -> None:
        """Parse a binary tab file and reconstruct the contents."""
        with self.file.open("rb") as fh:
            # Header is the same for all types
            self.file_header = c_windowstab.file_header(fh)

            # fileType == 1  # 0 is unsaved, 1 is saved, 9 is settings?
            self.is_saved = self.file_header.fileType == 1

            # Tabs can be saved to a file with a filename on disk, or unsaved (kept in the TabState folder).
            # Depending on the file's saved state, different header fields are present
            self.tab_header = (
                c_windowstab.tab_header_saved(fh) if self.is_saved else c_windowstab.tab_header_unsaved(fh)
            )

            # There appears to be a optionsVersion field that specifies the options that are passed.
            # At the moment of writing, it is not sure whether this specifies a version or a number of bytes
            # that is parsed, so just going with the 'optionsVersion' type for now.
            # We don't use the options, but since they are required for the CRC32 checksum
            # we store the byte representation
            if self.tab_header.optionsVersion == 0:
                # No options specified
                self.options = b""
            elif self.tab_header.optionsVersion == 1:
                self.options = c_windowstab.options_v1(fh).dumps()
            elif self.tab_header.optionsVersion == 2:
                self.options = c_windowstab.options_v2(fh).dumps()
            else:
                # Raise an error, since we don't know how many bytes future optionVersions will occupy.
                # Now knowing how many bytes to parse can mess up the alignment and structs.
                raise NotImplementedError("Unknown Windows Notepad tab option version")

            # If the file is not saved to disk and no fixedSizeBlockLength is present, an extra checksum stub
            # is present. So parse that first
            if not self.is_saved and self.tab_header.fixedSizeBlockLength == 0:
                # Two unknown bytes before the CRC32
                tab_header_crc32_stub = c_windowstab.tab_header_crc32_stub(fh)

                # Calculate CRC32 of the header and check if it matches
                actual_header_crc32 = _calc_crc32(
                    self.file_header.dumps()[3:]
                    + self.tab_header.dumps()
                    + self.options
                    + tab_header_crc32_stub.dumps()[:-4]
                )
                if tab_header_crc32_stub.crc32 != actual_header_crc32:
                    logging.warning(
                        "CRC32 mismatch in header of file: %s (expected=%s, actual=%s)",
                        self.file.name,
                        tab_header_crc32_stub.crc32.hex(),
                        actual_header_crc32.hex(),
                    )

            # Used to store the final content
            self.content = ""

            # In the case that a fixedSizeDataBlock is present, this value is set to a nonzero value
            if self.tab_header.fixedSizeBlockLength > 0:
                # So we parse the fixed size data block
                self.data_entry = c_windowstab.fixed_size_data_block(fh)

                # The header (minus the magic) plus all data is included in the checksum
                actual_crc32 = _calc_crc32(
                    self.file_header.dumps()[3:] + self.tab_header.dumps() + self.options + self.data_entry.dumps()[:-4]
                )

                if self.data_entry.crc32 != actual_crc32:
                    logging.warning(
                        "CRC32 mismatch in single-block file: %s (expected=%s, actual=%s)",
                        self.file.name,
                        self.data_entry.crc32.hex(),
                        actual_crc32.hex(),
                    )

                # Add the content of the fixed size data block to the tab content
                self.content += self.data_entry.data

            # Used to store the deleted content, if available
            deleted_content = ""

            # If fixedSizeBlockLength in the header has a value of zero, this means that the entire file consists of
            # variable-length blocks. Furthermore, if there is any remaining data after the
            # first fixed size blocks, as indicated by the value of hasRemainingVariableDataBlocks,
            # also continue we also want to continue parsing
            if self.tab_header.fixedSizeBlockLength == 0 or (
                self.tab_header.fixedSizeBlockLength > 0 and self.data_entry.hasRemainingVariableDataBlocks == 1
            ):
                # Here, data is stored in variable-length blocks. This happens, for example, when several
                # additions and deletions of characters have been recorded and these changes have not been 'flushed'

                # Since we don't know the size of the file up front, and offsets don't necessarily have to be in order,
                # a list is used to easily insert text at offsets
                text = []

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
                                self.file.name,
                                data_entry.crc32.hex(),
                                actual_crc32.hex(),
                            )

                        # Insert the text at the correct offset.
                        for idx in range(data_entry.nAdded):
                            text.insert(data_entry.offset + idx, data_entry.data[idx])

                    elif data_entry.nDeleted > 0:
                        # Create a new slice. Include everything up to the offset,
                        # plus everything after the nDeleted following bytes
                        deleted_content += "".join(text[data_entry.offset : data_entry.offset + data_entry.nDeleted])
                        text = text[: data_entry.offset] + text[data_entry.offset + data_entry.nDeleted :]

                # Join all the characters to reconstruct the original text within the variable-length data blocks
                text = "".join(text)

                # Finally, add the reconstructed text to the tab content
                self.content += text

        # Set None if no deleted content was found
        self.deleted_content = deleted_content if deleted_content else None


class WindowsNotepadPlugin(EditorPlugin):
    """Windows notepad tab content plugin."""

    __namespace__ = "windowsnotepad"

    GLOB = "AppData/Local/Packages/Microsoft.WindowsNotepad_*/LocalState/TabState/*.bin"

    def __init__(self, target: Target):
        super().__init__(target)
        self.users_tabs: set[TargetPath, UnixUserRecord | WindowsUserRecord] = set()
        for user_details in self.target.user_details.all_with_home():
            for tab_file in user_details.home_path.glob(self.GLOB):
                # These files contain information on different settings / configurations, and are skipped for now.
                if tab_file.name.endswith(".1.bin") or tab_file.name.endswith(".0.bin"):
                    continue

                self.users_tabs.add((tab_file, user_details.user))

    def check_compatible(self) -> None:
        if not self.users_tabs:
            raise UnsupportedPluginError("No Windows Notepad tab files found")

    @alias("tabs")
    @export(record=[WindowsNotepadSavedTabRecord, WindowsNotepadUnsavedTabRecord])
    def history(self) -> Iterator[WindowsNotepadSavedTabRecord | WindowsNotepadUnsavedTabRecord]:
        """Return contents from Windows 11 Notepad tabs - and its deleted content if available.

        Windows Notepad application for Windows 11 is now able to restore both saved and unsaved tabs when you re-open
        the application.

        Resources:
            - https://github.com/fox-it/dissect.target/pull/540
            - https://github.com/JustArion/Notepad-Tabs
            - https://github.com/ogmini/Notepad-Tabstate-Buffer
            - https://github.com/ogmini/Notepad-State-Library
            - https://github.com/Nordgaren/tabstate-util
            - https://github.com/Nordgaren/tabstate-util/issues/1
            - https://medium.com/@mahmoudsoheem/new-digital-forensics-artifact-from-windows-notepad-527645906b7b

        Yields ``WindowsNotepadSavedTabRecord`` or ``WindowsNotepadUnsavedTabRecord`` records:

        .. code-block:: text

            ts              (datetime): The modification time of the tab.
            content         (string):   The content of the tab.
            path            (path):     The path to the tab file.
            deleted_content (string):   The deleted content of the tab, if available.
            digest          (digest):   A digest of the tab content.
            saved_path      (path):     The path where the tab was saved.
        """
        for file, user in self.users_tabs:
            tab = WindowsNotepadTab(file)

            if tab.is_saved:
                yield WindowsNotepadSavedTabRecord(
                    ts=wintimestamp(tab.tab_header.timestamp),
                    editor="windowsnotepad",
                    content=tab.content,
                    path=tab.file,
                    deleted_content=tab.deleted_content,
                    digest=digest((None, None, tab.tab_header.sha256.hex())),
                    saved_path=tab.tab_header.filePath,
                    source=file,
                    _user=user,
                    _target=self.target,
                )

            else:
                yield WindowsNotepadUnsavedTabRecord(
                    editor="windowsnotepad",
                    content=tab.content,
                    deleted_content=tab.deleted_content,
                    path=tab.file,
                    source=file,
                    _user=user,
                    _target=self.target,
                )
