#!/usr/bin/env python
from __future__ import absolute_import, print_function

import argparse
import logging
import pprint

from dissect.target import plugin


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase output verbosity")
    args = parser.parse_args()

    if args.verbose == 1:
        logging.basicConfig(level=logging.ERROR)
    elif args.verbose == 2:
        logging.basicConfig(level=logging.WARNING)
    elif args.verbose == 3:
        logging.basicConfig(level=logging.INFO)
    elif args.verbose >= 4:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.CRITICAL)

    pluginlist = plugin.generate()
    print(f"PLUGINS = \\\n{pprint.pformat(pluginlist)}")


if __name__ == "__main__":
    main()
