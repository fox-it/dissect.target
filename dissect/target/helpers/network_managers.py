from collections import defaultdict
from configparser import ConfigParser, MissingSectionHeaderError
from io import StringIO
from re import compile, sub
from typing import Any, Callable, Match, Optional, Union

from defusedxml import ElementTree

from dissect.target.helpers.fsutil import TargetPath
from dissect.target.target import Target

try:
    import yaml

    PY_YAML = True
except ImportError:
    PY_YAML = False


class Template:
    """Class that represents a parsing template. Linux network configuration files can be parsed according to the
    options specified within this template.

    Args:
        name: Name of the parsing template.
        parser: A function or object to parse a Linux network configuration file with.
        sections: Configuration sections to look for in the specified configuration file.
        options: Configuration options to look for in the specified configuration file (ip, dns, dhcp, etc.).
    """

    def __init__(self, name: str, parser: Any, sections: list[str], options: list[str]) -> None:
        self.name = name
        self.parser = parser

        self.sections = sections
        self.options = options

    def set_name(self, name: str) -> None:
        """Sets the name of the the used parsing template to the name of the discovered network manager."""
        self.name = name

    def create_config(self, path: TargetPath) -> Union[dict, None]:
        """Create a network config dictionary based on the configured template and supplied path.

        Args:
            Path: Path to the to be parsed config file.

        Returns:
            A dictionary based on the provided configured template, else None
        """

        if not path.exists() or path.is_dir():
            self.target.log.debug("Failed to get config file %s", path)
            config = None

        if self.name == "netplan":
            config = self._parse_netplan_config(path)
        elif self.name == "wicked":
            config = self._parse_wicked_config(path)
        elif self.name == "interfaces":
            config = self._parse_text_config(("#"), " ", path)
        elif isinstance(self.parser, ConfigParser):
            config = self._parse_configparser_config(path)
        return config

    def _parse_netplan_config(self, fh: TargetPath) -> Union[dict, None]:
        """Internal function to parse a netplan YAML based configuration file into a dict.

        Args:
            fh: A file-like object to the configuration file to be parsed.

        Returns:
            Dictionary containing the parsed YAML based configuration file.
        """
        if PY_YAML:
            return self.parser(stream=fh.open(), Loader=yaml.FullLoader)
        else:
            self.target.log.error("Failed to parse %s. Cannot import PyYAML", self.name)
            return None

    def _parse_wicked_config(self, fh: TargetPath) -> dict:
        """Internal function to parse a wicked XML based configuration file into a dict.

        Args:
            fh: A file-like object to the configuration file to be parsed.

        Returns:
            Dictionary containing the parsed xml based Linux network manager based configuration file.
        """
        # nasty workaround for namespaced XML without namespace (xlmns) definitions
        # we have to replace the ":" for this with "___" (three underscores) to make the xml config non-namespaced.
        pattern = compile(r"(?<=\n)\s+(<.+?>)")
        replace_match: Callable[[Match]] = lambda match: match.group(1).replace(":", "___")
        text = sub(pattern, replace_match, fh.open("rt").read())

        xml = self.parser(file=StringIO(text))
        return self._parse_xml_config(xml, self.sections, self.options)

    def _parse_configparser_config(self, fh: TargetPath) -> dict:
        """Internal function to parse ConfigParser compatible configuration files into a dict.

        Args:
            fh: A file-like object to the configuration file to be parsed.

        Returns:
            Dictionary containing the parsed ConfigParser compatible configuration file.
        """
        try:
            self.parser.read_string(fh.open("rt").read(), fh.name)
            return self.parser._sections
        except MissingSectionHeaderError:
            # configparser does like config files without headers, so we inject a header to make it work.
            self.parser.read_string(f"[{self.name}]\n" + fh.open("rt").read(), fh.name)
            return self.parser._sections

    def _parse_text_config(self, comments: str, delim: str, fh: TargetPath) -> dict:
        """Internal function to parse a basic plain text based configuration file into a dict.

        Args:
            comments: A string value defining the comment style of the configuration file.
            delim: A string value defining the delimiters used in the configuration file.
            fh: A file-like object to the configuration file to be parsed.

        Returns:
            Dictionary with a parsed plain text based Linux network manager configuration file.
        """
        config = defaultdict(dict)
        option_dict = {}
        fh = fh.open("rt")

        for line in fh.readlines():
            if line.startswith(comments):
                continue
            for option in self.options:
                if option in line:
                    entry = line.split(delim, maxsplit=1)[1].rstrip()
                    option_dict[option] = entry

        for section in self.sections:
            config[section] = option_dict

        return dict(config)

    def _parse_xml_config(self, xml: ElementTree, sections: list, options: list) -> dict:
        """Internal function to parse a xml based Linux network manager based configuration file into a dict.

        Args:
            xml: An XML ElementTree object to convert to a dict
            sections: Configuration sections to look-up in the specified XML ElementTree
            options: Configuration options to look-up in the specified XML ElementTree

        Returns:
            Dictionary containing the parsed xml based Linux network manager based configuration file.
        """
        xml_dict = {}
        for section in sections:
            tag = section
            # as a side-effect of escaping the ":" value we have to escape values containing ":" here as well.
            section = section.replace(":", "___")
            for element in (element for element in xml.findall(".//") if element.tag == section):
                text = element.text.strip()
                # a non-empty text field indicates that we are done searching for values
                if text:
                    xml_dict[tag] = {tag: text}
                else:
                    for option, value in (
                        (option, element.find(option)) for option in options if element.find(option) is not None
                    ):
                        xml_dict[tag] = {option: value.text}
        return xml_dict


class Parser:
    """Class that represents a parser. This class translates the config created from a Template into a generic
    configuration dictionary

    Args:
        target: Target to parse the config from.
        config_globs: Glob patterns to obtain config files from.
        template: Template object to create a config from.
    """

    def __init__(self, target: Target, config_globs: list[str], template: Template) -> None:
        self.target = target
        self.template = template

        self.sections = self.template.sections
        self.options = self.template.options
        self.config_globs = config_globs

    def parse(self) -> defaultdict:
        """Returns a translated dictionary of network configuration properties.

        Returns:
            Dictionary containing network configuration properties for interface, dhcp, ips, gateways, dns, and netmask.
        """

        template = defaultdict(set)

        for path in self.expand_config_file_paths():
            config = self.template.create_config(path)

            for key, value in self.translate_network_config(config):
                template[key].add(value)
        return template

    def translate_network_config(self, config_dict: dict) -> list[tuple[str, Any]]:
        """Translates a parsed network configuration property to its generalized form:

        Returns:
            List containing the translated property and its value.
        """
        translated_values = []
        for section in self.sections:
            for option in self.options:
                value = self._get_option(config_dict, option, section)
                key = self.translate(value, option)
                if key:
                    translated_values.append((key, value))
        return translated_values

    def expand_config_file_paths(self) -> list[TargetPath]:
        """Expands all globbed config file path to discovery network configuration files.

        Returns:
            List containing the found network configuration files.
        """
        config_files = []

        for glob in self.config_globs:
            glob = glob.lstrip("/")
            for path in self.target.fs.path().glob(glob):
                if path.is_file():
                    config_files.append(path)
        return config_files

    def translate(self, value: Any, option: str) -> str:
        """Translates the passed option value name to its corrensponding generalized option name.

        Returns:
            Translated option name.
        """
        translation_table = {
            "interface": ["name", "iface", "device"],
            "dhcp": ["bootproto", "dhcp", "dhcp4", "dhcpserver", "method"],
            "ips": ["ip", "address1", "addresses", "ipaddr", "address"],
            "gateway": ["gateway4", "gateway"],
            "dns": ["dns", "dns1"],
        }

        for translation_key, translation_values in translation_table.items():
            if any([translation_value in option for translation_value in translation_values]) and value:
                return translation_key

    def _get_option(self, config: dict, option: str, section: Optional[str] = None) -> Union[str, Callable]:
        """Internal function to get arbitrary options values from a parsed (non-translated) dictionary.

        Args:
            config: Configuration dictionary to obtain a option from.
            option: Option value to search for in the configuration dictionary.
            section: Section within the configuration dictionaty to look for the option value.

        Returns:
            Value(s) corrensponding to that network configuration option.
        """
        if section:
            config = config[section]
        for key, value in config.items():
            if key == option:
                return value
            elif isinstance(value, dict):
                if option in value:
                    return value[option]
                else:
                    return self._get_option(value, option)


class NetworkManager:
    """This class represents a Linux network managers on a given Linux based target. Detects if the network manager is
    active based on available configuration files and paths.

    Args:
        name: Name of the network manager to detect
        detection_globs: Glob patterns to detect network manager with.
        config_flobs: Glob patterns to retreive possible configuration files belonging to this network manager.
    """

    def __init__(self, name: str, detection_globs: tuple[str], config_globs: tuple[str]) -> None:
        self.target = None
        self.parser = None
        self.config = None

        self.name = name
        self.config_globs = (config_globs,) if isinstance(config_globs, str) else config_globs
        self.detection_globs = (detection_globs,) if isinstance(detection_globs, str) else detection_globs

    def detect(self, target: Optional[Target] = None) -> bool:
        """Detects if the network manager is active on the target

        Returns:
            Whether a certain network manager is detected on the target
        """
        for path in self.detection_globs:
            path = path.lstrip("/")

            if len(list(target.fs.path().glob(path))):
                target.log.debug("Found compatible network manager: %s", self.name)
                return True

        return False

    def register(self, target: Target, template: Template) -> bool:
        """Sets the detected parsing template and target the network manager.

        Args:
            target: Target object to register to this NetworkManager class.
            template: Parsing Template object to register to this NetworkManager class.

        Returns:
            Whether the registration process was executed succesfully.
        """
        self.target = target
        self.parser = Parser(target, self.config_globs, template)

        # Check if the unglobbed config files actually exists.
        # If not, nothing to parse. Thus we can skip this network manager.
        if self.parser.expand_config_file_paths():
            target.log.debug("Applying parsing template %s to network manager %s", template.name, self.name)
            target.log.debug("Registered network manager: %s as active", self.name)
            return True
        else:
            self.target, self.parser = None, None
            target.log.error("Failed to register network manager %s as active.", self.name)
            return False

    def parse(self) -> None:
        """Parse the network configuration for this network manager."""
        if self.registered:
            self.config = self.parser.parse()
        else:
            self.target.log.error("Network manager %s is not registered. Cannot parse config.", self.name)

    @property
    def interface(self) -> set:
        return self.config.get("interface")

    @property
    def ips(self) -> set:
        return self.config.get("ips")

    @property
    def dns(self) -> set:
        return self.config.get("dns")

    @property
    def dhcp(self) -> bool:
        # we do some post-processing on dhcp values to get a final boolean verdict
        return self._dhcp()

    @property
    def gateway(self) -> set:
        return self.config.get("gateway")

    @property
    def netmask(self) -> set:
        return self.config.get("netmask")

    @property
    def registered(self) -> bool:
        if self.target and self.parser:
            return True
        else:
            return False

    def _dhcp(self) -> set:
        """Internal function to translate DHCP values to their boolean equivalent.

        Returns:
            Set of boolean values which indicate if DHCP is enabled for an interface.
        """
        # dhcp is either on or off per interface, so we require some extra post processing to give a accurate verdict.
        translation_table = {
            True: ("yes", "dhcp", "auto"),
            False: ("no", "none", "static", "manual"),
        }

        translated_value = set()

        if self.config.get("dhcp"):
            for dhcp_value in self.config.get("dhcp", ""):
                if isinstance(dhcp_value, bool):
                    return translated_value.add(dhcp_value)

                for key, value in translation_table.items():
                    if dhcp_value.lower() in value:
                        translated_value.add(key)
        else:
            translated_value.add(False)

        return translated_value

    def __repr__(self) -> str:
        return f"<NetworkManager {self.name}>"


class LinuxNetworkManager:
    """This class represents a collection of available network managers on a linux target as a collection of
    NetworkManager objects.

    Args:
        target: Target to discover and obtain network information from.
    """

    def __init__(self, target: Target):
        self.managers = []
        self.target = target

    def discover(self) -> None:
        """Discover which defined network managers are active on the target.

        Registers the discovered network managers as active for parsing later on.
        """
        for manager in MANAGERS:
            if manager.detect(self.target):
                if manager.register(self.target, TEMPLATES[manager.name]):
                    self.managers.append(manager)

    def get_config_value(self, attr: str) -> list[set]:
        """Return the specified value from a network configuration option.

        Returns:
            List containing the values corrensponding to that configuration option.
        """
        values = []
        for manager in self.managers:
            manager.parse()
            value = getattr(manager, attr, None)
            if value:
                values.append(value)
        return values


MANAGERS = [
    NetworkManager(
        "netctl",
        ("/etc/netctl/examples/*", "/usr/lib/systemd/system/netctl*.service"),
        ("/etc/netctl/*"),
    ),
    NetworkManager(
        "NetworkManager",
        ("/usr/bin/nmcli", "/usr/bin/nmtui", "/etc/NetworkManager/NetworkManager.conf", "/usr/lib/NetworkManager/*"),
        ("/etc/NetworkManager/system-connections/*"),
    ),
    NetworkManager(
        "systemd-networkd",
        ("/lib/systemd/system/systemd-networkd.servic*"),
        (
            "/etc/systemd/network/*.network",
            "/run/systemd/network/*.network",
            "/usr/lib/systemd/network/*.network",
        ),
    ),
    NetworkManager(
        "wicd",
        ("/usr/sbin/wicd", "/etc/dbus-1/system.d/wicd.*", "/etc/wicd/*.conf"),
        ("/etc/wicd/wire*-*.conf"),
    ),
    NetworkManager(
        "wicked",
        ("/usr/sbin/wicked*", "/usr/lib/systemd/system/wicked.*", "/etc/dbus-1/system.d/org.opensuse.Network.*"),
        ("/etc/wicked/ifconfig/*.xml"),
    ),
    NetworkManager(
        "netplan",
        ("/usr/sbin/netplan", "/usr/share/dbus-1/system.d/io.netplan.Netplan.conf"),
        ("/etc/netplan/*.yaml"),
    ),
    NetworkManager(
        "ifupdown",
        ("/usr/sbin/ifup", "/usr/sbin/ifdown"),
        ("/etc/sysconfig/network-scripts/ifcfg-*", "/etc/sysconfig/network/ifcfg-*"),
    ),
    NetworkManager(
        "interfaces",
        ("/usr/sbin/ifup", "/usr/sbin/ifdown", "/usr/sbin/ifquery"),
        ("/etc/network/interfaces"),
    ),
]

TEMPLATES = {
    "netctl": Template(
        "netctl",
        ConfigParser(delimiters=("=", " "), comment_prefixes="#", dict_type=dict),
        ["netctl"],
        ["address", "gateway", "dns", "ip"],
    ),
    "netplan": Template("netplan", yaml.load if PY_YAML else None, ["network"], ["addresses", "dhcp4", "gateway4"]),
    "NetworkManager": Template(
        "NetworkManager",
        ConfigParser(delimiters=("="), comment_prefixes="#", dict_type=dict),
        ["ipv4"],
        ["address1", "dns"],
    ),
    "systemd-networkd": Template(
        "systemd-networkd",
        ConfigParser(delimiters=("="), comment_prefixes=("#", ";"), dict_type=dict),
        ["Network", "Match"],
        ["address", "dhcp", "dns", "name", "dhcpserver"],
    ),
    "wicked": Template("wicked", ElementTree, ["ipv4:static", "name"], ["./address/local", "name"]),
    "ifupdown": Template(
        "ifupdown",
        ConfigParser(delimiters=("=", " "), comment_prefixes=("#"), dict_type=dict, strict=False),
        ["ifupdown"],
        ["ipaddr", "bootproto", "dns", "gateway", "name", "device", "dns1"],
    ),
    "interfaces": Template("interfaces", None, ["interfaces"], ["iface", "address", "gateway"]),
}
