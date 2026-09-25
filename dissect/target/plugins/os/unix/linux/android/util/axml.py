from __future__ import annotations

from enum import IntEnum
from struct import unpack
from typing import TYPE_CHECKING, BinaryIO
from xml.etree.ElementTree import ElementTree

from defusedxml import ElementTree as ET

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


class ResourceType(IntEnum):
    NULL = 0x0
    STRING_POOL = 0x1
    TABLE = 0x2
    XML = 0x3
    NAMESPACE_START = 0x100
    NAMESPACE_END = 0x101
    ELEMENT_START = 0x102
    ELEMENT_END = 0x103
    CDATA = 0x104
    RESOURCE_MAP = 0x180


class AttributeType(IntEnum):
    NULL = 0x0
    REFERENCE = 0x1
    ATTRIBUTE = 0x2
    STRING = 0x3
    FLOAT = 0x4
    DIMENSION = 0x5
    FRACTION = 0x6
    DYNAMIC_REFERENCE = 0x7
    DYNAMIC_ATTRIBUTE = 0x8
    INT_DEC = 0x10
    INT_HEX = 0x11
    INT_BOOL = 0x12
    COLOR_ARGB8 = 0x1C
    COLOR_RGB8 = 0x1D
    COLOR_ARGB4 = 0x1E
    COLOR_RGB4 = 0x1F


class Flags(IntEnum):
    UTF8 = 1 << 8


class AXmlFile:
    """Android AXML / ARSC implementation.

    Can be used to parse ``AndroidManifest.xml`` files in APK files.

    References:
        - https://github.com/androguard/axml
        - https://androguard.readthedocs.io/en/latest/intro/axml.html
    """

    def __init__(self, path: Path | None = None, fh: BinaryIO | None = None):
        if path:
            self.path = path
            self.fh = path.open("rb")
        elif fh:
            self.path = None
            self.fh = fh
        else:
            raise ValueError("path or fh argument required")

        self.strings = []
        self.styles = []
        self.namespace_stack = []
        self.namespace_undeclared = []
        self.resource_ids = []

    def __repr__(self) -> str:
        return f"<AXmlFile path={self.path or self.fh}>"

    @property
    def tree(self) -> ElementTree:
        output = "".join(self.iter_tokens())
        return ElementTree(ET.fromstring(output))

    def _read_bytes(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("invalid offset in AXML binary")

        b = self.fh.read(n)

        if len(b) != n:
            raise ValueError("Unexpected end of input for AXML binary")

        return b

    def _read_ushort(self) -> int:
        return int.from_bytes(self._read_bytes(2), "little", signed=False)

    def _read_uint(self) -> int:
        return int.from_bytes(self._read_bytes(4), "little", signed=False)

    def _read_ulong(self) -> int:
        return int.from_bytes(self._read_bytes(8), "little", signed=False)

    def _read_arsc_header(self) -> tuple[ResourceType, int, int]:
        ty = self._read_ushort()
        header_size = self._read_ushort()
        size = self._read_uint()

        return ResourceType(ty), header_size, size

    def _read_string(self) -> str:
        idx = self._read_uint()

        if idx > len(self.strings):
            return ""
        return self.strings[idx]

    def _read_string_pool(self) -> None:
        start_offset = self.fh.tell()

        ty, _, size = self._read_arsc_header()

        if ty != ResourceType.STRING_POOL:
            raise ValueError("Expected first chunk to be a string pool")

        str_count = self._read_uint()
        style_count = self._read_uint()

        flags = self._read_uint()

        if flags & Flags.UTF8:
            char_size = 1
            encoding = "utf-8"
        else:
            char_size = 2
            encoding = "utf-16"

        if (str_offset := self._read_uint()) == 0:
            str_offset = size

        if (style_offset := self._read_uint()) == 0:
            style_offset = size

        str_offsets = [self._read_uint() for _ in range(str_count)]
        style_offsets = [self._read_uint() for _ in range(style_count)]

        cur_offset = self.fh.tell() - start_offset

        if cur_offset <= str_offset <= style_offset:
            self._read_bytes(str_offset - cur_offset)
            str_bytes = self._read_bytes(style_offset - str_offset)
            style_bytes = self._read_bytes(size - style_offset)
        elif cur_offset <= style_offset <= str_offset:
            self._read_bytes(style_offset - cur_offset)
            style_bytes = self._read_bytes(str_offset - style_offset)
            str_bytes = self._read_bytes(size - str_offset)
        else:
            raise ValueError("Invalid string and style offset in AXML binary")

        for offset in str_offsets:
            if offset + (char_size * 2) > len(str_bytes):
                raise ValueError("Invalid string offset in AXML binary")

            length1 = int.from_bytes(str_bytes[offset : offset + char_size], "little", signed=False)
            length2 = int.from_bytes(str_bytes[offset + char_size : offset + char_size * 2], "little", signed=False)

            mask = 0x80 << (8 * (char_size - 1))

            if (length1 & mask) != 0:
                length = ((length1 & ~mask) << (8 * char_size)) | length2
                start = offset + (char_size * 2)
            else:
                length = length1
                start = offset + char_size

            end = start + (length * char_size)

            self.strings.append(str_bytes[start:end].decode(encoding))

        self.styles.extend([style_bytes[offset:] for offset in style_offsets])

    def _read_element_attr(self, size: int) -> tuple[str, str]:
        attr_ns_uri = self._read_string()

        attr_name = self._read_string()
        attr_str = self._read_uint()
        attr_ty = AttributeType(self._read_uint() >> 24)
        attr_data = self._read_uint()

        match attr_ty:
            case AttributeType.INT_DEC:
                attr_str = str(attr_data)
            case AttributeType.STRING:
                attr_str = self.strings[attr_str]
            case AttributeType.REFERENCE:
                pkg = "android:" if attr_data >> 24 == 1 else ""
                attr_str = f"@{pkg}{hex(attr_data)}"
            case AttributeType.INT_BOOL:
                attr_str = "true" if attr_data == 0 else "false"
            case AttributeType.FLOAT:
                attr_str = str(unpack("=f", attr_data.to_bytes(4, "little", signed=False))[0])
            case (
                AttributeType.COLOR_RGB8
                | AttributeType.COLOR_ARGB8
                | AttributeType.COLOR_RGB4
                | AttributeType.COLOR_ARGB4
            ):
                attr_str = f"#{hex(attr_data)}"
            case _:
                attr_str = str(attr_data)

        attr_name = self._format_with_ns_prefix(attr_ns_uri, attr_name)

        self._read_bytes(size - 20)

        return attr_name, attr_str

    def _read_element_start(self) -> str:
        ns_uri = self._read_string()
        name = self._read_string()
        name = self._format_with_ns_prefix(ns_uri, name)

        attr_start = self._read_ushort()
        attr_size = self._read_ushort()

        if attr_start != 20:
            raise ValueError("Invalid AXML: attribute start should be 20")

        if attr_size < 20:
            raise ValueError("Invalid AXML: attribute size can not be less than 20")

        attr_count = self._read_uint()
        attrs = []

        if self.namespace_undeclared:
            for prefix, ns in self.namespace_undeclared:
                attrs.append((f"xmlns:{prefix}", ns))

            self.namespace_undeclared = []

        # Class attribute, not sure what this does yet.
        self._read_uint()

        attrs.extend([self._read_element_attr(attr_size) for _ in range(attr_count)])

        attrs = "".join([f' {k}="{v}"' for k, v in attrs])

        return f"<{name}{attrs}>"

    def _format_with_ns_prefix(self, namespace: str, name: str) -> str:
        if namespace == "":
            return name

        for prefix, nsitem in self.namespace_stack:
            if nsitem == namespace:
                if prefix != "":
                    return f"{prefix}:{name}"
                return name

        if "://" in namespace:
            return f"{{{namespace}}}:{name}"
        return f"{namespace}:{name}"

    def iter_tokens(self) -> Iterator[str]:
        start = self.fh.tell()

        _, _, size = self._read_arsc_header()
        self._read_string_pool()

        while (self.fh.tell() - start) < size:
            ty, chunk_header_size, chunk_size = self._read_arsc_header()

            if ty == ResourceType.RESOURCE_MAP:
                count = (chunk_size - chunk_header_size) // 4
                self.resource_ids.extend([self._read_uint() for _ in range(count)])
                continue

            # Line number
            _ = self._read_uint()
            # Comment index
            _ = self._read_uint()

            match ty:
                case ResourceType.NAMESPACE_START:
                    prefix = self._read_string()
                    uri = self._read_string()
                    self.namespace_stack.append((prefix, uri))
                    self.namespace_undeclared.append((prefix, uri))
                case ResourceType.NAMESPACE_END:
                    # prefix and uri should match popped namespace, we dont really care if they don't.
                    self._read_string()
                    self._read_string()
                    self.namespace_stack.pop()
                    self.namespace_undeclared = []
                case ResourceType.ELEMENT_START:
                    yield self._read_element_start()
                case ResourceType.ELEMENT_END:
                    ns_uri = self._read_string()
                    name = self._read_string()

                    name = self._format_with_ns_prefix(ns_uri, name)

                    yield f"</{name}>"
                case ResourceType.CDATA:
                    text = self._read_string()

                    self._read_uint()
                    self._read_uint()

                    yield text

                case ResourceType.STRING_POOL | ResourceType.XML:
                    continue
