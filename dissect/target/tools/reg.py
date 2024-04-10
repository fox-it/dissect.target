#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import argparse
import itertools
import logging

from dissect.target import Target
from dissect.target.exceptions import (
    RegistryError,
    RegistryKeyNotFoundError,
    TargetError,
)
from dissect.target.helpers.regutil import RegistryKey
from dissect.target.tools.utils import (
    catch_sigpipe,
    configure_generic_arguments,
    process_generic_arguments,
)

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


@catch_sigpipe
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
    parser.add_argument("-d", "--depth", type=int, const=0, nargs="?", default=1, help="max depth of subkeys to print")
    parser.add_argument("-l", "--length", type=int, default=100, help="max length of key value to print")

    configure_generic_arguments(parser)
    args = parser.parse_args()

    process_generic_arguments(args)

    try:
        for target in Target.open_all(args.targets):
            if not target.has_function("registry"):
                target.log.error("Target has no Windows Registry")
                continue

            try:
                keys = target.registry.keys(args.key)
                first_key = next(keys)

                print(target)

                for key in itertools.chain([first_key], keys):
                    try:
                        if args.value:
                            print(key.value(args.value))
                        else:
                            recursor(key, args.depth, 0, args.length)
                    except RegistryError:
                        log.exception("Failed to find registry value")

            except (RegistryKeyNotFoundError, StopIteration):
                target.log.error("Key %r does not exist", args.key)

            except Exception as e:
                target.log.error("Failed to iterate key: %s", e)
                target.log.debug("", exc_info=e)
    except TargetError as e:
        log.error(e)
        log.debug("", exc_info=e)
        parser.exit(1)


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
        except NotImplementedError:
            continue

    if depth == 0:
        return

    for subkey in key.subkeys():
        recursor(subkey, depth - 1, indent + 2, max_length)


if __name__ == "__main__":
    main()
