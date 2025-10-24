#!/usr/bin/env python
from __future__ import annotations

import argparse
import logging
import textwrap
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dissect.cstruct.utils import hexdump

from dissect.target.containers.hdd import HddContainer
from dissect.target.exceptions import TargetError
from dissect.target.helpers.logging import get_logger
from dissect.target.plugin import arg
from dissect.target.tools.shell import python_shell
from dissect.target.tools.utils.cli import (
    catch_sigpipe,
    configure_generic_arguments,
    open_target,
    process_generic_arguments,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from dissect.target.container import Container
    from dissect.target.filesystem import Filesystem
    from dissect.target.target import DiskCollection, FilesystemCollection, Target, VolumeCollection
    from dissect.target.volume import Volume

log = get_logger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


def indent(value: str, width: int = 1) -> None:
    """Indent and print value"""
    print(textwrap.indent(str(value), " " * (width * 4)))


def scope(*args, **kwargs) -> Callable[..., Any]:
    def decorator(obj: Callable[..., Any]) -> Callable[..., Any]:
        obj.__scope__ = args
        return obj

    return decorator


def _apply_scope(t: Target, scope: str) -> None:
    if scope == "disk":
        log.info("Only loading disks")
        return

    if scope == "volume":
        log.info("Only loading disks and volumes")
        t.disks.apply()
        t.volumes.apply(filesystems=False)
        return

    if scope == "filesystem":
        log.info("Only loading disks, volumes and filesystems")
        t.disks.apply()
        t.volumes.apply()
        t.filesystems.apply()
        return

    raise ValueError(f"Unknown scope: {scope}")


def _get_scope(t: Target, scope: str) -> DiskCollection | VolumeCollection | FilesystemCollection:
    if scope == "disk":
        return t.disks
    if scope == "volume":
        return t.volumes
    if scope == "filesystem":
        return t.filesystems

    raise ValueError(f"Unknown scope: {scope}")


def _get_obj(t: Target, args: argparse.Namespace) -> Iterator[Container | Volume | Filesystem]:
    entries = _get_scope(t, args.scope)

    if args.index is None:
        yield from entries
    elif args.index >= len(entries):
        raise IndexError(f"{args.scope.capitalize()} index {args.index} out of range (max {len(entries) - 1})")
    else:
        yield entries[args.index]


@scope("disk", "volume")
@arg("-s", "--skip", type=int, default=0, help="skip offset bytes from the beginning")
@arg("-n", "--length", type=int, default=512, help="number of bytes to read")
def cmd_hexdump(t: Target, args: argparse.Namespace) -> None:
    """hexdump some bytes"""
    for obj in _get_obj(t, args):
        print(f"# {obj}")

        obj.seek(args.skip)
        hexdump(obj.read(args.length), offset=args.skip)

        print()


def _info_hdd(obj: HddContainer) -> None:
    print(f"path={obj.hdd.path}")
    print()

    print("# Storage data")
    for storage in obj.hdd.descriptor.storage_data.storages:
        print(f"start={storage.start} end={storage.end}")
        for image in storage.images:
            indent(f"guid={image.guid}")
            indent(f"file={image.file}")
            indent(f"type={image.type}")
            print()

    print("# Snapshots")
    print(f"top_guid={obj.hdd.descriptor.snapshots.top_guid}")
    for shot in obj.hdd.descriptor.snapshots.shots:
        indent(f"guid={shot.guid}")
        indent(f"parent={shot.parent}")
        print()

    print("# Stream info")
    for storage, hds in obj.stream.streams:
        print(f"start={storage.start} end={storage.end}")
        i = 1
        while hds.parent is not None:
            indent(hds.fh, i)
            i += 1
            hds = hds.parent


@scope("disk", "volume")
def cmd_info(t: Target, args: argparse.Namespace) -> None:
    """print information"""
    for obj in _get_obj(t, args):
        print(f"# {obj}")

        if isinstance(obj, HddContainer):
            _info_hdd(obj)


@scope("disk", "volume", "filesystem")
def cmd_list(t: Target, args: argparse.Namespace) -> None:
    """list available items"""
    entries = _get_scope(t, args.scope)

    print(f"{args.scope.capitalize()}s:")
    for i, entry in enumerate(entries):
        print(f"[{i}]: {entry}")


@scope("disk", "volume", "filesystem")
def cmd_shell(t: Target, args: argparse.Namespace) -> None:
    """open (I)Python shell"""
    try:
        python_shell([t])
    except TargetError as e:
        log.error("Error opening shell: %s", e)  # noqa: TRY400
        log.debug("", exc_info=e)


def _add_cmds(parser: argparse.ArgumentParser, scope: str) -> None:
    sub = parser.add_subparsers(dest="cmd", required=False, help="available commands")

    for name, obj in globals().items():
        if not name.startswith("cmd_") or not callable(obj) or scope not in getattr(obj, "__scope__", ()):
            continue

        cmd_parser = argparse.ArgumentParser(add_help=False)
        cmd_parser.add_argument(
            "-i", "--index", type=int, default=None, help="index of the item to debug", metavar="INDEX"
        )
        for args, kwargs in getattr(obj, "__args__", []):
            cmd_parser.add_argument(*args, **kwargs)
        cmd_parser.set_defaults(handler=obj)

        sub.add_parser(name[4:], help=obj.__doc__, parents=[cmd_parser])


@catch_sigpipe
def main() -> int:
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="dissect.target",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
    )
    scope = parser.add_subparsers(dest="scope", required=True, help="scope to debug")

    base = argparse.ArgumentParser(add_help=False)
    base.add_argument("target", type=Path, help="Target to load", metavar="TARGET")
    configure_generic_arguments(base)

    parser_disk = scope.add_parser("disk", help="debug disks", parents=[base])
    _add_cmds(parser_disk, "disk")

    parser_volume = scope.add_parser("volume", help="debug volumes", parents=[base])
    _add_cmds(parser_volume, "volume")

    parser_filesystem = scope.add_parser("filesystem", help="debug filesystems", parents=[base])
    _add_cmds(parser_filesystem, "filesystem")

    args, _ = parser.parse_known_args()
    process_generic_arguments(parser, args)

    try:
        t = open_target(args, apply=False)
    except TargetError as e:
        log.error(e)  # noqa: TRY400
        log.debug("", exc_info=e)
        return 1

    _apply_scope(t, args.scope)

    if args.index is not None and args.index >= len(_get_scope(t, args.scope)):
        print(f"{args.scope.capitalize()} index {args.index} out of range")
        print()
        cmd_list(t, args)
        return 1

    if args.cmd is None:
        cmd_list(t, args)
    else:
        args.handler(t, args)

    return 0


if __name__ == "__main__":
    main()
