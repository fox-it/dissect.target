#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging
import shutil
import sys

from dissect.util.stream import RangeStream

from dissect.target import Target
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
    parser.add_argument("target", metavar="TARGET", help="Target to dd from")
    parser.add_argument("-w", "--write", default="-", help="output file")
    parser.add_argument("-o", "--offset", type=int, default=0, help="offset to read from.")
    parser.add_argument("-b", "--bytes", type=int, default=-1, help="amount of bytes to read")

    configure_generic_arguments(parser)

    args = parser.parse_args()

    process_generic_arguments(args)

    t = Target.open(args.target)

    if len(t.disks) > 1:
        parser.exit("Target has more than one disk")

    if not len(t.disks):
        parser.exit("Target has no disks")

    fhin = t.disks[0]

    if args.write == "-":
        fhout = sys.stdout.buffer
    else:
        fhout = open(args.write, "wb")

    try:
        size = args.bytes if args.bytes != -1 else fhin.size
        fhin = RangeStream(fhin, offset=args.offset, size=size)

        shutil.copyfileobj(fhin, fhout)
    finally:
        # We should not close the stdout buffer
        if fhout is not sys.stdout.buffer:
            fhout.close()


if __name__ == "__main__":
    main()
