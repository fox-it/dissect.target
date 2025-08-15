from __future__ import annotations

import json as jsonlib

from dissect.target.helpers.docs import INDENT_STEP, get_docstring
from dissect.target.loader import LOADERS_BY_SCHEME
from dissect.target.plugin import Plugin, arg, export


class LoaderListPlugin(Plugin):
    """Plugin to list the available loaders."""

    def check_compatible(self) -> None:
        pass

    @export(output="none")
    @arg("-j", "--json", action="store_true", help="output in JSON format")
    def loaders(self, json: bool = False) -> None:
        """List the available loaders."""

        loaders_info = {}
        for key, loader in LOADERS_BY_SCHEME.items():
            try:
                docstring = get_docstring(loader, "No documentation.").splitlines()[0].strip()
                loaders_info[key] = docstring
            except ImportError:  # noqa: PERF203
                continue

        loaders = sorted(loaders_info.items())

        if json:
            print(jsonlib.dumps([{"name": name, "description": desc} for name, desc in loaders]), end="")

        else:
            print("Available loaders:")
            for loader_name, loader_description in loaders:
                print(f"{INDENT_STEP}{loader_name} - {loader_description}")
