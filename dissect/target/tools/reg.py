#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import argparse
import logging

from dissect.target import Target
from dissect.target.exceptions import RegistryError
from dissect.target.tools.utils import (
    configure_generic_arguments,
    process_generic_arguments,
)

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


def main():
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="dissect.target",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
    )
    parser.add_argument("targets", metavar="TARGETS", nargs="+", help="Targets to load")
    parser.add_argument("-k", "--key", required=True, help="key to query")
    parser.add_argument("-kv", "--value", help="value to query")
    parser.add_argument("-d", "--depth", type=int, const=0, nargs="?", default=1)

    configure_generic_arguments(parser)
    args = parser.parse_args()

    process_generic_arguments(args)

    for target in Target.open_all(args.targets):
        try:
            if args.value:
                for key in target.registry.keys(args.key):
                    try:
                        print(key.value(args.value))
                    except RegistryError:
                        continue
            else:
                try:
                    print(target)
                    for key in target.registry.keys(args.key):
                        recursor(key, args.depth, 0)
                except RegistryError:
                    log.exception("Failed to find registry value")
        except Exception:
            log.exception("Failed to iterate key")


def recursor(key, depth, indent):
    print(" " * indent + f"+ {key.name!r} ({key.ts})")

    for r in key.values():
        try:
            print(" " * indent + f"  - {r.name!r} {repr(r.value)[:100]}")
        except NotImplementedError:
            continue

    if depth == 0:
        return

    for subkey in key.subkeys():
        recursor(subkey, depth - 1, indent + 2)


if __name__ == "__main__":
    main()
