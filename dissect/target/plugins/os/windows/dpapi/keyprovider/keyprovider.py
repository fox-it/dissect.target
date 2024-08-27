from dissect.target.plugin import InternalNamespacePlugin


class KeyProviderPlugin(InternalNamespacePlugin):
    __namespace__ = "_dpapi_keyprovider"

    def check_compatible(self) -> None:
        return None
