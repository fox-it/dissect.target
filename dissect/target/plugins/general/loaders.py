import json

from dissect.target.helpers.docs import INDENT_STEP, get_docstring
from dissect.target.loader import LOADERS_BY_SCHEME
from dissect.target.plugin import Plugin, arg, export


class LoaderListPlugin(Plugin):
    """Plugin to list the available loaders."""

    def check_compatible(self) -> None:
        pass

    @export(output="none")
    @arg("--json", dest="output_json", action="store_true")
    def loaders(self, output_json: bool = False) -> None:
        """List the available loaders."""

        loaders_info = {}
        for key, loader in LOADERS_BY_SCHEME.items():
            try:
                docstring = get_docstring(loader, "No documentation.").splitlines()[0].strip()
                loaders_info[key] = docstring
            except ImportError:
                continue

        loaders = sorted(loaders_info.items())

        if output_json:
            print(json.dumps([{"name": name, "description": desc} for name, desc in loaders]), end="")

        else:
            print("Available loaders:")
            for loader_name, loader_description in loaders:
                print(f"{INDENT_STEP}{loader_name} - {loader_description}")
