#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import json
import logging
from pathlib import Path
from typing import Union

from dissect.target import Target
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.tools.query import record_output
from dissect.target.tools.utils import (
    catch_sigpipe,
    configure_generic_arguments,
    process_generic_arguments,
)

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
        ("string[]", "children"),
    ],
)


log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


@catch_sigpipe
def main():
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="target-info",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
    )
    parser.add_argument("targets", metavar="TARGETS", nargs="*", help="Targets to display info from")
    parser.add_argument("--from-file", nargs="?", type=Path, help="file containing targets to load")
    parser.add_argument("-d", "--delimiter", default=" ", action="store", metavar="','")
    parser.add_argument("-s", "--strings", action="store_true", help="print output as string")
    parser.add_argument("-r", "--record", action="store_true", help="print output as record")
    parser.add_argument("-j", "--json", action="store_true", help="output records as pretty json")
    parser.add_argument("-J", "--jsonlines", action="store_true", help="output records as one-line json")
    configure_generic_arguments(parser)

    args = parser.parse_args()

    process_generic_arguments(args)

    if not args.targets and not args.from_file:
        parser.error("too few arguments")

    if args.from_file:
        if not args.from_file.exists():
            parser.error(f"--from-file {args.from_file} does not exist")

        targets = args.from_file.read_text().splitlines()
        while targets[-1] == "":
            targets = targets[:-1]
        args.targets = targets

    for i, target in enumerate(Target.open_all(args.targets)):
        try:
            if args.jsonlines:
                print(json.dumps(get_target_info(target), default=str))
            elif args.json:
                print(json.dumps(get_target_info(target), indent=4, default=str))
            elif args.record:
                rs = record_output(args.strings)
                rs.write(InfoRecord(**get_target_info(target), _target=target))
            else:
                if i > 0:
                    print("-" * 70)
                print_target_info(target)
        except Exception as e:
            target.log.error("Exception in retrieving information for target: `%s`", target, exc_info=e)


def get_target_info(target: Target) -> dict[str, Union[str, list[str]]]:
    return {
        "disks": get_disks_info(target),
        "volumes": get_volumes_info(target),
        "children": get_children_info(target),
        "hostname": target.hostname,
        "domain": get_optional_func(target, "domain"),
        "ips": target.ips,
        "os_family": target.os,
        "os_version": target.version,
        "architecture": target.architecture,
        "language": get_optional_func(target, "language"),
        "timezone": get_optional_func(target, "timezone"),
        "install_date": get_optional_func(target, "install_date"),
        "last_activity": get_optional_func(target, "activity"),
    }


def get_optional_func(target: Target, func: str) -> Union[str, None]:
    if target.has_function(func):
        return getattr(target, func)


def print_target_info(target: Target) -> None:
    print(target)

    for name, value in get_target_info(target).items():
        if name in ["disks", "volumes", "children"]:
            if not any(value):
                continue
            print(f"\n{name.capitalize()}")
            for i in value:
                values = " ".join([f'{k}="{v}"' for k, v in i.items()])
                print(f"- <{name.capitalize()[:-1].replace('re', '')} {values}>")
            continue

        if isinstance(value, list):
            value = ", ".join(value)

        if name == "hostname":
            print()

        print(f"{name.capitalize().replace('_', ' ')}" + (14 - len(name)) * " " + f" : {value}")


def get_disks_info(target: Target) -> list[dict[str, Union[str, int]]]:
    return [{"type": d.__class__.__name__, "size": d.size} for d in target.disks]


def get_volumes_info(target: Target) -> list[dict[str, Union[str, int]]]:
    return [{"name": v.name, "size": v.size, "fs": v.fs.__class__.__name__} for v in target.volumes]


def get_children_info(target: Target) -> list[dict[str, str]]:
    return [{"type": c.type, "path": str(c.path)} for c in target.list_children()]


if __name__ == "__main__":
    main()
