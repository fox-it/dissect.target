from dissect.target.helpers.docs import INDENT_STEP, get_docstring
from dissect.target.loader import LOADERS_BY_SCHEME
from dissect.target.plugin import Plugin, export


class LoaderListPlugin(Plugin):
    """Plugin to list the available loaders."""

    def check_compatible(self) -> None:
        pass

    @export(output="none")
    def loaders(self):
        """List the available loaders."""

        loaders_info = {}
        for key, loader in LOADERS_BY_SCHEME.items():
            try:
                docstring = get_docstring(loader, "No documentation.").splitlines()[0].strip()
                loaders_info[key] = docstring
            except ImportError:
                continue

        print("Available loaders:")
        for loader_name, loader_description in sorted(loaders_info.items()):
            print(f"{INDENT_STEP}{loader_name} - {loader_description}")
