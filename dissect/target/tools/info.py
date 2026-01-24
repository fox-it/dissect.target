#!/usr/bin/env python
from __future__ import annotations

import argparse
import functools
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dissect.target.exceptions import TargetError
from dissect.target.helpers.logging import get_logger
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.tools.query import record_output
from dissect.target.tools.utils.cli import (
    catch_sigpipe,
    configure_generic_arguments,
    open_targets,
    process_generic_arguments,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from dissect.target.target import Target


InfoRecord = TargetRecordDescriptor(
    "target/info",
    [
        ("datetime", "last_activity"),
        ("datetime", "install_date"),
        ("net.ipaddress[]", "ips"),
        ("string", "os_family"),
        ("string", "os_version"),
        ("string", "architecture"),
        ("string[]", "language"),
        ("string", "timezone"),
        ("string[]", "disks"),
        ("string[]", "volumes"),
        ("string[]", "mounts"),
        ("string[]", "children"),
    ],
)


log = get_logger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


@catch_sigpipe
def main() -> int:
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="target-info",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
    )
    parser.add_argument("targets", metavar="TARGETS", nargs="*", help="Targets to display info from")
    parser.add_argument("--from-file", nargs="?", type=Path, help="file containing targets to load")
    parser.add_argument("-s", "--strings", action="store_true", help="print output as string")
    parser.add_argument("-r", "--record", action="store_true", help="print output as record")
    parser.add_argument("-j", "--json", action="store_true", help="output records as pretty json")
    parser.add_argument("-J", "--jsonlines", action="store_true", help="output records as one-line json")
    configure_generic_arguments(parser)

    args, _ = parser.parse_known_args()

    if not args.targets and not args.from_file:
        parser.error("too few arguments")

    if args.from_file:
        if not args.from_file.exists():
            parser.error(f"--from-file {args.from_file} does not exist")

        targets = args.from_file.read_text().splitlines()
        while targets[-1] == "":
            targets = targets[:-1]
        args.targets = targets

    process_generic_arguments(parser, args)

    try:
        for i, target in enumerate(open_targets(args)):
            try:
                target_info = get_target_info(target, args.recursive)
                if args.jsonlines:
                    print(json.dumps(target_info, default=str))
                elif args.json:
                    print(json.dumps(target_info, indent=4, default=str))
                elif args.record:
                    rs = record_output(args.strings)
                    rs.write(InfoRecord(**target_info, _target=target))
                else:
                    if i > 0:
                        print("-" * 70)
                    print_target_info(target, target_info)
            except Exception as e:  # noqa: PERF203
                target.log.error("Exception in retrieving information for target: `%s`, use `-vv` for details", target)  # noqa: TRY400
                target.log.debug("", exc_info=e)
    except TargetError as e:
        log.error(e)  # noqa: TRY400
        log.debug("", exc_info=e)
        return 1

    return 0


def get_target_info(target: Target, recursive: bool = False) -> dict[str, str | list[str]]:
    return {
        "disks": get_disks_info(target),
        "volumes": get_volumes_info(target),
        "mounts": get_mounts_info(target),
        "children": get_children_info(target, recursive),
        "hostname": get_property(target, "hostname"),
        "domain": get_property(target, "domain"),
        "ips": get_property(target, "ips"),
        "os_family": get_property(target, "os"),
        "os_version": get_property(target, "version"),
        "architecture": get_property(target, "architecture"),
        "language": get_property(target, "language"),
        "timezone": get_property(target, "timezone"),
        "install_date": get_property(target, "install_date"),
        "last_activity": get_property(target, "activity"),
    }


def get_property(target: Target, func: str) -> str | None:
    try:
        if target.has_function(func):
            return getattr(target, func)
    except Exception as e:
        log.warning("Error executing %s: %s", func, e)
        log.debug("", exc_info=e)
    return None


def print_target_info(target: Target, target_info: dict[str, str | list[str]]) -> None:
    print(target)

    for name, value in target_info.items():
        if name in ["disks", "volumes", "mounts", "children"]:
            if not any(value):
                continue
            print(f"\n{name.capitalize()}")
            for i in value:
                values = " ".join([f"{k}={v!r}" for k, v in i.items()])
                print(f"- <{name.capitalize()[:-1].replace('re', '')} {values}>")
            continue

        if isinstance(value, list):
            value = ", ".join(map(str, value))

        if isinstance(value, datetime):
            value = value.isoformat(timespec="microseconds")

        if name == "hostname":
            print()

        print(f"{name.capitalize().replace('_', ' '):14s} : {value}")


def catch_errors(func: Callable[[Target], list[dict]]) -> Callable[[Target], list[dict]]:
    """Catch all errors and return dict with error if encountered."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> list[dict[str, Any]]:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            log.warning("Error executing %s: %s", func.__name__, e)
            log.debug("", exc_info=e)
            return [{"error": str(e)}]

    return wrapper


@catch_errors
def get_disks_info(target: Target) -> list[dict[str, str | int]]:
    return [{"type": d.__type__, "size": d.size} for d in target.disks]


@catch_errors
def get_volumes_info(target: Target) -> list[dict[str, str | int | None]]:
    return [{"name": v.name, "size": v.size, "fs": v.fs.__type__ if v.fs else None} for v in target.volumes]


@catch_errors
def get_mounts_info(target: Target) -> list[dict[str, str | None]]:
    return [{"fs": fs.__type__, "path": path} for path, fs in target.fs.mounts.items()]


@catch_errors
def get_children_info(target: Target, recursive: bool = False) -> list[dict[str, str]]:
    return [
        {"id": child_id, "type": child.type, "name": child.name, "path": str(child.path)}
        for child_id, child in target.list_children(recursive=recursive)
    ]


if __name__ == "__main__":
    main()
