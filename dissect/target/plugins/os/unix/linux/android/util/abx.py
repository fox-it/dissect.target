from __future__ import annotations

import base64
import struct
from enum import IntEnum
from typing import TYPE_CHECKING, Any, BinaryIO
from xml.etree.ElementTree import Element, ElementTree, SubElement

from dissect.cstruct import u16, u32, u64

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


class XmlType(IntEnum):
    START_DOCUMENT = 0
    END_DOCUMENT = 1
    START_TAG = 2
    END_TAG = 3
    TEXT = 4
    CDSECT = 5
    ENTITY_REF = 6
    IGNORABLE_WHITESPACE = 7
    PROCESSING_INSTRUCTION = 8
    COMMENT = 9
    DOCDECL = 10
    ATTRIBUTE = 15


class DataType(IntEnum):
    NULL = 1 << 4
    STRING = 2 << 4
    STRING_INTERNED = 3 << 4
    BYTES_HEX = 4 << 4
    BYTES_BASE64 = 5 << 4
    INT = 6 << 4
    INT_HEX = 7 << 4
    LONG = 8 << 4
    LONG_HEX = 9 << 4
    FLOAT = 10 << 4
    DOUBLE = 11 << 4
    BOOLEAN_TRUE = 12 << 4
    BOOLEAN_FALSE = 13 << 4


class AbxFile:
    """Android binary XML (ABX) implementation.

    References:
        - https://www.cclsolutionsgroup.com/post/android-abx-binary-xml
        - https://cs.android.com/android/platform/superproject/+/master:frameworks/base/core/java/com/android/internal/util/BinaryXmlSerializer.java
        - https://cs.android.com/android/platform/superproject/+/master:frameworks/base/core/java/com/android/internal/util/BinaryXmlPullParser.java
    """

    def __init__(self, path: Path | None = None, fh: BinaryIO | None = None, *, to_str: bool = False) -> None:
        if path:
            self.path = path
            self.fh = path.open("rb")
        elif fh:
            self.path = None
            self.fh = fh
        else:
            raise ValueError("No path or file handle provided")

        if (magic := self.fh.read(4)) != b"ABX\x00":
            raise ValueError(f"Unexpected magic value {magic!r}")

        self.READ_MAP: dict[DataType, Callable] = {
            DataType.NULL: lambda: None,
            DataType.BOOLEAN_TRUE: lambda: True,
            DataType.BOOLEAN_FALSE: lambda: False,
            DataType.INT: lambda: u32(self.fh.read(4), endian="big", sign=True),
            DataType.INT_HEX: lambda: f"{u32(self.fh.read(4), endian='big', sign=True):x}",
            DataType.LONG: lambda: u64(self.fh.read(8), endian="big", sign=True),
            DataType.LONG_HEX: lambda: f"{u64(self.fh.read(8), endian='big', sign=True):x}",
            DataType.FLOAT: lambda: struct.unpack(">f", self.fh.read(4))[0],
            DataType.DOUBLE: lambda: struct.unpack(">d", self.fh.read(8))[0],
            DataType.BYTES_HEX: self._read_bytes,
            DataType.BYTES_BASE64: lambda: base64.b64encode(self._read_bytes()).decode().strip(),
            DataType.STRING: self._read_string,
            DataType.STRING_INTERNED: self._read_string_interned,
        }

        self.INTERNED_STRINGS = []
        self.tree = self.read(to_str=to_str)

    def __repr__(self) -> str:
        return f"<AbxFile path={self.path.name if self.path else self.fh}>"

    def _read_token(self) -> tuple[XmlType, DataType]:
        """Reads a byte to determine :class:`XmlType` and :class:`DataType`."""
        token = self.fh.read(1)
        xml_type = XmlType(token[0] & 0x0F)  # lower nibble
        data_type = DataType(token[0] & 0xF0)  # upper nibble
        return xml_type, data_type

    def _read_bytes(self) -> bytes:
        len = u16(self.fh.read(2), endian="big", sign=False)
        return self.fh.read(len)

    def _read_string(self) -> str:
        len = u16(self.fh.read(2), endian="big", sign=False)
        return self.fh.read(len).decode()

    def _read_string_interned(self) -> str:
        ref = u16(self.fh.read(2), endian="big", sign=True)
        if ref == -1:
            value = self._read_string()
            self.INTERNED_STRINGS.append(value)
        else:
            value = self.INTERNED_STRINGS[ref]
        return value

    def read(self, to_str: bool = False) -> ElementTree:
        """Read the ABX file, returns XML :class:`ElementTree`."""
        elements: list[Element] = []
        document_open = False
        root_closed = False

        # Start by placing everything in a root element. If we later discover the document
        # only has one element in this root, we replace the root element with that element.
        root = Element("root")
        elements.append(root)

        while True:
            xml_type, data_type = self._read_token()

            if xml_type == XmlType.START_DOCUMENT:
                if data_type != DataType.NULL:
                    raise ValueError(f"XmlType.START_DOCUMENT should have DataType.NULL, got {data_type!r}")
                document_open = True

            elif xml_type == XmlType.END_DOCUMENT:
                if data_type != DataType.NULL:
                    raise ValueError(f"XmlType.END_DOCUMENT should have DataType.NULL, got {data_type!r}")
                if len(elements) != 1:
                    raise ValueError(f"XmlType.END_DOCUMENT with unclosed elements ({elements!r}) at {self.fh.tell()}")
                if not document_open:
                    raise ValueError(f"XmlType.END_DOCUMENT before XmlType.START_DOCUMENT at {self.fh.tell()}")
                break

            elif xml_type == XmlType.START_TAG:
                if data_type != DataType.STRING_INTERNED:
                    raise ValueError(f"XmlType.START_TAG should have DataType.STRING_INTERNED, got {data_type!r}")
                if not document_open:
                    raise ValueError(f"XmlType.START_TAG before XmlType.START_DOCUMENT at {self.fh.tell()}")
                if root_closed:
                    raise ValueError(f"XmlType.START_TAG after XmlType.END_TAG for root element at {self.fh.tell()}")

                name = self._read_string_interned()
                if len(elements) == 0:
                    element = Element(name)
                    root = element
                else:
                    element = SubElement(elements[-1], name)
                elements.append(element)

            elif xml_type == XmlType.END_TAG:
                if data_type != DataType.STRING_INTERNED:
                    raise ValueError(f"XmlType.END_TAG should have DataType.STRING_INTERNED, got {data_type!r}")
                if len(elements) == 1:
                    raise ValueError(f"XmlType.END_TAG without any elements in stack at {self.fh.tell()}")

                name = self._read_string_interned()

                if name != (other := elements[-1].tag):
                    raise ValueError(f"XmlType.END_TAG for {name!r} encountered, expected for {other!r}")

                last = elements.pop()
                if len(elements) == 0:
                    root_closed = True
                    root = last

            elif xml_type == XmlType.TEXT:
                value = self._read_string()
                if len(elements[-1]):
                    if len(value.strip()) == 0:
                        continue
                    raise ValueError(f"XmlType.TEXT with mixed content encountered at {self.fh.tell()}")

                if elements[-1].text is None:
                    elements[-1].text = value
                else:
                    elements[-1].text += value

            elif xml_type == XmlType.ATTRIBUTE:
                if len(elements) == 1:
                    raise ValueError(f"XmlType.ATTRIBUTE encountered outside any open element at {self.fh.tell()}")

                name = self._read_string_interned()
                if name in elements[-1].attrib:
                    raise ValueError(
                        f"Duplicate XmlType.ATTRIBUTE {name} encountered for element {elements[-1]} at {self.fh.tell()}"
                    )

                callable = self.READ_MAP.get(data_type)
                if not callable:
                    raise ValueError(f"Unsupported DataType {data_type!r}")

                value = callable()
                elements[-1].attrib[name] = str(value) if to_str else value

        if not (root_closed or (len(elements) == 1 and elements[0] is root)):
            raise ValueError("Document contains unclosed elements")

        # If the root we created at the start only contains one child, we make that node the root.
        if len(children := root.findall("./")) == 1:
            root = children[0]

        return ElementTree(root)


class AbxSettingsFile(AbxFile):
    """Android binary ABX settings file parser."""

    def get(self, key: str, *, value_only: bool = True) -> Any:
        """Return the value of the given setting name."""
        if (node := self.tree.find(f"./settings/setting[@name='{key}']")) is not None:
            return node.attrib["value"] if value_only else node

        return None

    def get_node(self, key: str) -> Any:
        return self.get(key, value_only=False)
