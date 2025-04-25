#!/usr/bin/env python
from __future__ import annotations

import argparse
import logging
import shutil
import sys

from dissect.util.stream import RangeStream

from dissect.target.exceptions import TargetError
from dissect.target.target import Target
from dissect.target.tools.utils import (
    catch_sigpipe,
    configure_generic_arguments,
    process_generic_arguments,
)

log = logging.getLogger(__name__)
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
    parser.add_argument("target", metavar="TARGET", help="Target to dd from")
    parser.add_argument("-w", "--write", default="-", help="output file")
    parser.add_argument("-o", "--offset", type=int, default=0, help="offset to read from.")
    parser.add_argument("-b", "--bytes", type=int, default=-1, help="amount of bytes to read")
    configure_generic_arguments(parser)

    args, rest = parser.parse_known_args()
    process_generic_arguments(args, rest)

    try:
        t = Target.open(args.target)
    except TargetError as e:
        log.error(e)  # noqa: TRY400
        log.debug("", exc_info=e)
        return 1

    if len(t.disks) > 1:
        log.error("Target has more than one disk")
        return 1

    if not len(t.disks):
        log.error("Target has no disks")
        return 1

    fhin = t.disks[0]

    fhout = sys.stdout.buffer if args.write == "-" else open(args.write, "wb")  # noqa: PTH123, SIM115

    try:
        size = args.bytes if args.bytes != -1 else fhin.size
        fhin = RangeStream(fhin, offset=args.offset, size=size)

        shutil.copyfileobj(fhin, fhout)
    finally:
        # We should not close the stdout buffer
        if fhout is not sys.stdout.buffer:
            fhout.close()

    return 0


if __name__ == "__main__":
    main()
