from dissect.target.loader import LOADERS, DirLoader
from dissect.target.plugin import Plugin, export


class LoaderListPlugin(Plugin):
    """Plugin to list the available loaders."""

    def check_compatible(self):
        return True

    @export(output="none")
    def loaders(self):
        """List the available loaders."""

        loader_names = sorted(getattr(loader, "attr", loader.__name__) for loader in LOADERS + [DirLoader])

        print("Available loaders:")
        for loader_name in loader_names:
            print(f"\t{loader_name}")
