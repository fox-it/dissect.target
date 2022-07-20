import itertools

from dissect.target.loader import LOADERS, DirLoader
from dissect.target.plugin import Plugin, export


class LoaderListPlugin(Plugin):
    """Plugin to list the available loaders."""

    def check_compatible(self):
        return True

    @export(output="none")
    def loaders(self):
        """List the available loaders."""

        loaders = itertools.chain(LOADERS, [DirLoader])
        loader_names = [loader.attr for loader in loaders]
        loader_names.sort()

        print("Available loaders:")
        for loader_name in loader_names:
            print(f"    {loader_name}")
