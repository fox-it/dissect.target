#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import json
import logging

from dissect.target import Target
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.tools.query import record_output
from dissect.target.tools.utils import (
    configure_generic_arguments,
    print_target_info,
    process_generic_arguments,
)

InfoRecord = TargetRecordDescriptor(
    "target/info",
    [
        ("string", "os_family"),
        ("string", "os_version"),
        ("string", "install_date"),
        ("string", "last_activity"),
        ("net.ipaddress[]", "ips"),
        ("string", "architecture"),
        ("string", "language"),
        ("string", "timezone"),
    ],
)


log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


def main():
    """target-info"""

    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="dissect.info",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
        add_help=False,
    )
    parser.add_argument("targets", metavar="TARGETS", nargs="*", help="Targets to display info from")
    parser.add_argument("--from-file", nargs="?", help="file containing targets to load")
    parser.add_argument("-d", "--delimiter", default=" ", action="store", metavar="','")
    parser.add_argument("-s", "--strings", action="store_true", help="print output as string")
    parser.add_argument("-r", "--record", action="store_true", help="print output as record")
    parser.add_argument("-j", "--json", action="store_true", help="output records as one-line json")
    parser.add_argument("-J", "--json-pretty", action="store_true", help="output records as pretty json")
    configure_generic_arguments(parser)

    args, rest = parser.parse_known_args()

    if not args.targets and ("-h" in rest or "--help" in rest):
        parser.print_help()
        parser.exit()

    process_generic_arguments(args)

    if not args.targets and not args.from_file:
        parser.error("too few arguments")

    if args.from_file:
        with open(args.from_file, "r") as f:
            targets = f.read().splitlines()
            while targets[-1] == "":
                targets = targets[:-1]
            args.targets = targets

    for target in Target.open_all(args.targets):

        if args.json:
            print(json.dumps(obj_target_info(target)))
        elif args.json_pretty:
            print(json.dumps(obj_target_info(target), indent=4))
        elif args.record:
            record = InfoRecord(
                os_family=target.os,
                os_version=target.version,
                ips=target.ips,
                architecture=target.architecture,
                install_date=target.installdate,
                last_activity=target.activity,
                language=target.language,
                timezone=target.timezone,
                _target=target,
            )
            rs = record_output(args.strings, args.json)
            rs.write(record)
        else:
            print_target_info(target)


def obj_target_info(target):
    return {
        "hostname": target.hostname,
        "os_family": target.os,
        "os_version": target.version,
        "architecture": target.architecture,
        "domain": target.domain,
        "ips": target.ips,
        "install_date": str(target.installdate),
        "last_activity": str(target.activity),
        "language": target.language,
        "timezone": target.timezone,
        "disks": [{"type": d.__class__.__name__, "size": d.size} for d in target.disks],
        "volumes": [{"name": v.name, "size": v.size, "fs": v.fs.__class__.__name__} for v in target.volumes],
    }


if __name__ == "__main__":
    main()
