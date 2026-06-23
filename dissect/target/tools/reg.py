#!/usr/bin/env python
from __future__ import annotations

import argparse
import itertools
import logging
import sys
from contextlib import nullcontext
from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.exceptions import (
    RegistryError,
    RegistryKeyNotFoundError,
    TargetError,
)
from dissect.target.helpers.logging import get_logger
from dissect.target.helpers.regutil import REG_FLEX_HEADER, write_reg_key
from dissect.target.plugins.os.windows.registry import RegistryPlugin
from dissect.target.tools.utils.cli import (
    catch_sigpipe,
    configure_generic_arguments,
    open_targets,
    process_generic_arguments,
)

if TYPE_CHECKING:
    from dissect.target.helpers.regutil import RegistryKey
    from dissect.target.target import Target


log = get_logger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


@catch_sigpipe
def main() -> int:
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="dissect.target",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
    )
    parser.add_argument("targets", metavar="TARGETS", nargs="+", help="Targets to load")
    parser.add_argument(
        "-k",
        "--key",
        action="append",
        metavar="KEY",
        dest="keys",
        help="key to query or export; can be repeated with --export to select multiple paths",
    )
    parser.add_argument("-kv", "--value", help="value to query")
    parser.add_argument("-d", "--depth", type=int, const=0, nargs="?", default=1, help="max depth of subkeys to print")
    parser.add_argument("-l", "--length", type=int, default=100, help="max length of key value to print")
    parser.add_argument(
        "-e",
        "--export",
        action="store_true",
        help="export registry keys to .reg file format instead of the default tree view",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="output file for --export (default: stdout)",
    )
    configure_generic_arguments(parser)

    args, _ = parser.parse_known_args()
    process_generic_arguments(parser, args)

    if not args.export and not args.keys:
        parser.error("argument -k/--key is required when not using --export")

    try:
        for target in open_targets(args):
            if not target.has_function("registry"):
                target.log.error("Target has no Windows Registry")
                continue

            if args.export:
                _export_keys(target, args)
            else:
                _query_key(target, args)

    except TargetError as e:
        log.error(e)  # noqa: TRY400
        log.debug("", exc_info=e)
        return 1

    return 0


def _query_key(target: Target, args: argparse.Namespace) -> None:
    """Query and print registry keys in tree format."""
    try:
        keys = target.registry.keys(args.keys)
        first_key = next(keys)

        print(target)

        for key in itertools.chain([first_key], keys):
            try:
                if args.value:
                    print(key.value(args.value))
                else:
                    recursor(key, args.depth, 0, args.length)
            except RegistryError:  # noqa: PERF203
                log.exception("Failed to find registry value")

    except (RegistryKeyNotFoundError, StopIteration):
        # Use the first key for the error message to preserve existing behaviour
        key_display = args.keys[0] if len(args.keys) == 1 else args.keys
        target.log.error("Key %r does not exist", key_display)  # noqa: TRY400

    except Exception as e:
        target.log.error("Failed to iterate key: %s", e)  # noqa: TRY400
        target.log.debug("", exc_info=e)


def _expand_key_path(key_path: str, shortnames: dict[str, str]) -> str:
    """Expand a registry shortname prefix to the canonical HKEY_* name.

    Args:
        key_path: A registry path, optionally starting with a shortname such
            as ``HKLM`` or ``SYSTEM``.
        shortnames: The shortname mapping from :attr:`RegistryPlugin.SHORTNAMES`.

    Returns:
        The path with the leading component expanded to its full name.
    """
    prefix, sep, rest = key_path.partition("\\")
    expanded = shortnames.get(prefix.upper(), prefix.upper())
    return f"{expanded}{sep}{rest}"


def _export_keys(target: Target, args: argparse.Namespace) -> None:
    shortnames = RegistryPlugin.SHORTNAMES
    paths: list[str] | None = args.keys

    cm = (
        Path(args.output).open("w", encoding="utf-8")  # noqa: SIM115
        if args.output
        else nullcontext(sys.stdout)
    )

    with cm as fh:
        fh.write(f"{REG_FLEX_HEADER}\n\n")
        fh.write(f"; Exported from: {target}\n")
        fh.write("; This .reg file was exported by target-reg (part of Dissect Target)\n")

        if paths:
            fh.write("; Registry paths exported:\n")
            for path in paths:
                fh.write(f";   {_expand_key_path(path, shortnames)}\n")

        fh.write("\n")

        export_paths = paths or list(shortnames.keys())
        for path in export_paths:
            expanded = _expand_key_path(path, shortnames)
            try:
                key = target.registry.key(path)
            except RegistryKeyNotFoundError:
                target.log.error("Key %r does not exist", path)  # noqa: TRY400
                continue
            except Exception as e:
                target.log.error("Failed to open key %r: %s", path, e)  # noqa: TRY400
                target.log.debug("", exc_info=e)
                continue
            write_reg_key(fh, key, expanded)


def recursor(key: RegistryKey, depth: int, indent: int, max_length: int = 100) -> None:
    class_name = ""
    if key.class_name:
        class_name = f" ({key.class_name})"

    print(" " * indent + f"+ {key.name!r} ({key.ts})" + class_name)

    for r in key.values():
        try:
            value = repr(r.value)
            if len(value) > max_length:
                value = value[:max_length] + "..."
            print(" " * indent + f"  - {r.name!r} {value}")
        except NotImplementedError:  # noqa: PERF203
            continue

    if depth == 0:
        return

    for subkey in key.subkeys():
        recursor(subkey, depth - 1, indent + 2, max_length)


if __name__ == "__main__":
    main()
