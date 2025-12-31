#!/usr/bin/env python3
"""
reg-export.py - Export Windows registry hives to .reg format using dissect.target
"""

import argparse
import sys
import time
from pathlib import Path

from dissect.target import Target
from dissect.target.helpers.regutil import VirtualHive, VirtualKey

# Define SHORTNAMES locally to avoid modifying dissect code
# Taken from registry.py in dissect.target.plugins.os.windows.registry
SHORTNAMES = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKCC": "HKEY_CURRENT_CONFIG",
    "HKCU": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKU": "HKEY_USERS",
}


def _escape_reg_string(value: str) -> str:
    """Escape special characters for .reg file format"""
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def export_registry(target: Target, paths: list) -> str:
    """Export registry keys and values recursively"""
    lines = []
    lines.append("Windows Registry Editor Version 5.00")
    lines.append("")

    for path in paths:
        print("Exporting path:", path)

        start_key = target.registry.key(path)
        _export_key(start_key, path, lines, path)

    return "\n".join(lines)


def _export_key(key: VirtualKey, path: str, lines: list, current_path: str = "") -> None:
    """Recursively export registry key"""
    try:
        if current_path:
            lines.append(f"[{current_path}]")
            lines.extend(_format_value(value) for value in key.values())
            lines.append("")

        for subkey in key.subkeys():
            subkey_path = f"{current_path}\\{subkey.name}".lstrip("\\")

            if path is None or subkey_path.startswith(path):
                lines.append(f"[{subkey_path}]")

                lines.extend(_format_value(value) for value in subkey.values())

                lines.append("")
                _export_key(subkey, path, lines, subkey_path)
    except Exception as e:
        print(f"Error processing key: {e}", file=sys.stderr)


def _format_value(value: VirtualKey) -> str:
    """Format registry value for .reg file"""
    name = _escape_reg_string(value.name)
    data = value.value

    if isinstance(data, bytes):
        hex_data = " ".join(f"{b:02x}" for b in data)
        return f'"{name}"=hex:{hex_data}'
    if isinstance(data, int):
        return f'"{name}"=dword:{data:08x}'
    return f'"{name}"="{_escape_reg_string(data)}"'


def _expand_shortname(key_path: str) -> str:
    """Expand registry shortnames to full names."""
    for short, full in SHORTNAMES.items():
        if key_path.startswith(short + "\\"):
            return full + key_path[len(short) :]
        if key_path == short:
            return full
    return key_path


def _parse_value(value_str: str) -> object:
    """Parse a value string from .reg format into appropriate Python type.

    Args:
        value_str (str): The value string from the .reg file.

    Returns:
        The parsed value (str, int, bytes, etc.).
    """
    value_str = value_str.strip()
    if value_str.startswith('"') and value_str.endswith('"'):
        # String value
        inner = value_str[1:-1]
        return inner.replace('\\"', '"').replace("\\\\", "\\")
    if value_str.startswith("dword:"):
        # DWORD value
        return int(value_str[6:], 16)
    if value_str.startswith("hex:"):
        # Binary data
        hex_part = value_str[4:]
        hex_part = hex_part.replace(",", "")
        return bytes.fromhex(hex_part)
    # Default to string
    return value_str


class RegHive(VirtualHive):
    """VirtualHive wrapper that expands registry shortnames in key lookups."""

    def key(self, key_path: str | None) -> VirtualKey:
        if key_path:
            key_path = _expand_shortname(key_path)
        return super().key(key_path)


def _load_reg(reg_content: str) -> RegHive:
    """Load a .reg file content into a RegHive (VirtualHive with shortname support)

    Args:
        reg_content (str): The content of the .reg file

    Returns:
        RegHive: The loaded virtual registry hive with shortname expansion
    """
    hive = RegHive()
    lines = reg_content.splitlines()
    current_key = None
    for line in lines:
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            key_path = line[1:-1]
            # Expand shortnames
            key_path = _expand_shortname(key_path)
            current_key = VirtualKey(hive, key_path)
            hive.map_key(key_path, current_key)
        elif "=" in line and current_key:
            name, value_str = line.split("=", 1)
            name = name.strip('"')
            value = _parse_value(value_str)
            current_key.add_value(name, value)
    return hive


def load_reg_from_file(filepath: str) -> RegHive:
    """Load a .reg file from the specified file path.

    Args:
        filepath (str): The path to the .reg file.

    Returns:
        RegHive: The loaded virtual registry hive.
    """
    with Path(filepath).open() as file:
        reg_content = file.read()
    return _load_reg(reg_content)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export Windows registry to .reg format")
    parser.add_argument("--target", help="Target to open with dissect.target")
    parser.add_argument("path", nargs="*", help="Registry paths to export (optional, exports all if none)")
    parser.add_argument("--output", default=None, help="Output file (default: reg-save-<epoch>.reg)")

    args = parser.parse_args()
    print("Processing paths:", args.path)
    if not args.target:
        parser.print_help()
        sys.exit(1)

    if args.output is None:
        args.output = f"reg-save-{int(time.time())}.reg"

    try:
        target = Target.open(args.target)
        output = export_registry(target, args.path)

        if output:
            with Path.open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"Registry exported to {args.output}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
