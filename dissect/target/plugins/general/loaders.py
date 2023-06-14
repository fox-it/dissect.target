from dissect.target.helpers.docs import INDENT_STEP
from dissect.target.loader import LOADERS, DirLoader
from dissect.target.plugin import Plugin, export


class LoaderListPlugin(Plugin):
    """Plugin to list the available loaders."""

    def check_compatible(self):
        return True

    @export(output="none")
    def loaders(self):
        """List the available loaders."""

        loader_names = sorted(loader.__name__ for loader in LOADERS + [DirLoader])

        print("Available loaders:")
        for loader_name in loader_names:
            print(f"{INDENT_STEP}{loader_name}")
