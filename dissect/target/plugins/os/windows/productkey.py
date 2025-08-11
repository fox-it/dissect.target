from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.cstruct import cstruct

from dissect.target.exceptions import RegistryValueNotFoundError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, alias, export

if TYPE_CHECKING:
    from collections.abc import Iterator

pid_def = """
struct DigitalProductId {
    DWORD   uiSize;
    SHORT   MajorVersion;
    SHORT   MinorVersion;
    CHAR    szProductId[24];
    DWORD   uiKeyIdx;
    CHAR    szEditionId[16];
    CHAR    bCDKey[16];
    DWORD   uiCloneStatus;
    DWORD   uiTime;
    DWORD   uiRandom;
    DWORD   uiLt;
    DWORD   uiLicenseData[2];
    CHAR    sOemId[8];
    DWORD   uiBundleId;
    CHAR    sHardwareIdStatic[8];
    DWORD   uiHardwareIdTypeStatic;
    DWORD   uiBiosChecksumStatic;
    DWORD   uiVolSerStatic;
    DWORD   uiTotalRamStatic;
    DWORD   uiVideoBiosChecksumStatic;
    CHAR    sHardwareIdDynamic[8];
    DWORD   uiHardwareIdTypeDynamic;
    DWORD   uiBiosChecksumDynamic;
    DWORD   uiVolSerDynamic;
    DWORD   uiTotalRamDynamic;
    DWORD   uiVideoBiosChecksumDynamic;
    DWORD   uiCRC32;
};

struct DigitalProductId4 {
    DWORD   uiSize;
    SHORT   MajorVersion;
    SHORT   MinorVersion;
    WCHAR   szAdvancedPid[64];
    WCHAR   szActivationId[64];
    WCHAR   szOemID[8];
    WCHAR   szEditionType[260];
    BYTE    bIsUpgrade;
    CHAR    bReserved[7];
    CHAR    bCDKey[16];
    CHAR    bCDKey256Hash[32];
    CHAR    b256Hash[32];
    WCHAR   szEditionId[64];
    WCHAR   szKeyType[64];
    WCHAR   szEULA[64];
};
"""

c_pid = cstruct().load(pid_def)

WindowsProductKeyRecord = TargetRecordDescriptor(
    "windows/product_key",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("string", "type"),
        ("string", "key"),
        ("path", "source"),
    ],
)


class WindowsProductKeyPlugin(Plugin):
    """Windows product key plugin."""

    KEY = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"

    # Try the more detailed DigitalProductId version 4 first
    VALUES = ("DigitalProductId4", "DigitalProductId")

    def check_compatible(self) -> None:
        if not self.target.has_function("registry") or not any(self.target.registry.values(self.KEY, self.VALUES)):
            raise UnsupportedPluginError("WindowsProductKeyPlugin plugin requires RegistryPlugin")

    @alias("license")
    @export(record=WindowsProductKeyRecord)
    def productkey(self) -> Iterator[WindowsProductKeyRecord]:
        """Yield Windows product key(s) of the target.

        References:
            - Reversing ``pidgen.dll`` and ````pidgenx.dll``.
            - https://www.licenturion.com/xp/fully-licensed-wpa.txt
            - https://github.com/Endermanch/XPKeygen
        """
        seen_keys = set()

        for key in self.target.registry.keys(self.KEY):
            for value in self.VALUES:
                try:
                    pid_value = key.value(value)
                except RegistryValueNotFoundError:
                    continue

                try:
                    s = getattr(c_pid, pid_value.name)(pid_value.value)
                except EOFError as e:
                    self.target.log.warning("Unable to decode %s structure: %s", pid_value.name, e)
                    self.target.log.debug("", exc_info=e)
                    continue

                if (cd_key := decode_cd_key(s.bCDKey)) in seen_keys:
                    continue

                seen_keys.add(cd_key)

                edition_type = getattr(s, "szEditionType", "").strip("\00")
                edition_id = (
                    s.szEditionId.decode().strip("\00")
                    if isinstance(s.szEditionId, bytes)
                    else s.szEditionId.strip("\00")
                )

                yield WindowsProductKeyRecord(
                    ts=key.ts,
                    name=f"{edition_type} {edition_id}".strip(),
                    type=getattr(s, "szKeyType", "").strip("\00"),
                    key=cd_key,
                    source=f"HKLM\\{key.path}\\{value}",
                    _target=self.target,
                )


def decode_cd_key(input: bytes | bytearray) -> str:
    """Decode the given bytes to a Windows CD key using a pseudo base24 implementation."""
    chars = "BCDFGHJKMPQRTVWXY2346789"
    output = ""

    if not isinstance(input, bytearray):
        input = bytearray(input)

    if is_win8 := (input[14] // 6) & 1:
        input[14] = (input[14] & 0xF7) | ((is_win8 & 2) * 4)

    for _ in range(25):
        c = 0
        for j in range(14, -1, -1):
            c = (c << 8) ^ input[j]
            input[j] = min(int(c / 24), 255)
            c = c % 24
        output = chars[c] + output

    if is_win8:
        if c == 0:
            output = "N" + output
        else:
            part = output[1 : 1 + c]
            output = output[1:].replace(part, part + "N")

    return "-".join([output[i * 5 : i * 5 + 5] for i in range(5)])
