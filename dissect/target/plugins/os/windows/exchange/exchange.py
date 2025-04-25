from __future__ import annotations

from dissect.target.exceptions import RegistryError, UnsupportedPluginError
from dissect.target.plugin import Plugin, export


class ExchangePlugin(Plugin):
    """Microsoft Exchange Server plugin."""

    __namespace__ = "exchange"

    def check_compatible(self) -> None:
        if not len(self.install_paths()):
            raise UnsupportedPluginError("No Exchange install path found")

    def install_paths(self) -> list[str]:
        paths = []
        key = "HKLM\\SOFTWARE\\Microsoft\\ExchangeServer"
        for reg_key in self.target.registry.keys(key):
            for subkey in reg_key.subkeys():
                try:
                    setup_key = subkey.subkey("Setup")
                    install_path = setup_key.value("MsiInstallPath").value
                    paths.append(install_path)
                except RegistryError:  # noqa: PERF203
                    pass

        return paths

    @export(output="none")
    def transport_agents(self) -> None:
        """Print the content of the config file for Transport Agents for Microsoft Exchange.

        A Transport Agent is additional software on a Microsoft Exchange server that allows for custom processing of
        email messages that go through the transport pipeline.

        References:
            - https://docs.microsoft.com/en-us/exchange/mail-flow/transport-agents/transport-agents?view=exchserver-2019
        """
        for path in self.install_paths():
            config_path = self.target.fs.path(path).joinpath("TransportRoles/Agents/agents.config")
            if not config_path.exists():
                continue

            print(config_path.open().read())
