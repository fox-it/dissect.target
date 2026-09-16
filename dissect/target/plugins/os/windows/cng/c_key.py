from __future__ import annotations

from dissect.cstruct import cstruct

# References:
# - https://learn.microsoft.com/en-us/windows/win32/seccng/cng-structures
cng_def = """
struct KEY_PROPERTY {
    DWORD               Size;
    DWORD               Type;
    DWORD               Unknown;
    DWORD               NameSize;
    DWORD               ValueSize;
    WCHAR               Name[NameSize / 2];
    CHAR                Value[ValueSize];
};

struct KEY_FILE {
    DWORD               Version;
    DWORD               Flags;
    DWORD               NameSize;
    WORD                Type;
    WORD                PropertyCount;
    DWORD               PropertySizes[PropertyCount];
    DWORD               KeyPropertiesSize;
    DWORD               KeySize;
    CHAR                SlackSpace[20 - PropertyCount * 4];
    WCHAR               Name[NameSize / 2];
    // KEY_PROPERTY     Properties[...];
};
"""

c_key = cstruct()
c_key.load(cng_def)
