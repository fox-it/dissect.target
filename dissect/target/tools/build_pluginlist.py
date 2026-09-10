#!/usr/bin/env python
from __future__ import annotations

import argparse
import logging
import textwrap

from dissect.target import plugin
from dissect.target.tools.utils.cli import get_dissect_target_version


def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"target-build-pluginlist {get_dissect_target_version()} : generate a static list of plugins. "
        f"This can be used to run dissect.target in some specific environments "
        f"such as binaries built with PyOxidizer, where plugin auto discovery dynamic location does not work",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase output verbosity")
    parser.add_argument("--version", action="version", version=get_dissect_target_version())
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
    template = """
    from dissect.target.plugin import (
        FailureDescriptor,
        FunctionDescriptor,
        FunctionDescriptorLookup,
        PluginDescriptor,
        PluginDescriptorLookup,
        PluginRegistry,
    )

    PLUGINS = {}
    """
    print(textwrap.dedent(template).format(pluginlist))

    return 0


if __name__ == "__main__":
    main()
