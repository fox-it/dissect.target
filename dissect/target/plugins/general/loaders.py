from __future__ import annotations

import json

from dissect.target.helpers.docs import INDENT_STEP, get_docstring
from dissect.target.loader import LOADERS_BY_SCHEME
from dissect.target.plugin import Plugin, arg, export


class LoaderListPlugin(Plugin):
    """Plugin to list the available loaders."""

    def check_compatible(self) -> None:
        pass

    @export(output="none")
    # NOTE: We would prefer to re-use arguments across plugins from argparse in query.py, but that is not possible yet.
    # For now we use --as-json, but in the future this should be changed to inherit --json from target-query.
    # https://github.com/fox-it/dissect.target/pull/841
    # https://github.com/fox-it/dissect.target/issues/889
    @arg("--as-json", dest="as_json", action="store_true", help="output in JSON format")
    def loaders(self, as_json: bool = False) -> None:
        """List the available loaders."""

        loaders_info = {}
        for key, loader in LOADERS_BY_SCHEME.items():
            try:
                docstring = get_docstring(loader, "No documentation.").splitlines()[0].strip()
                loaders_info[key] = docstring
            except ImportError:  # noqa: PERF203
                continue

        loaders = sorted(loaders_info.items())

        if as_json:
            print(json.dumps([{"name": name, "description": desc} for name, desc in loaders]), end="")

        else:
            print("Available loaders:")
            for loader_name, loader_description in loaders:
                print(f"{INDENT_STEP}{loader_name} - {loader_description}")
