from collections import defaultdict
from configparser import ConfigParser, MissingSectionHeaderError
from io import StringIO
from re import compile, sub
from typing import Any, Callable, Dict, List, Match, Tuple, Union
from xml.etree.ElementTree import ElementTree

from dissect.target.helpers.fsutil import TargetPath
from dissect.target.target import Target

try:
    import yaml

    PY_YAML = True
except ImportError:
    PY_YAML = False


class Template:
    def __init__(self, parser: Any, sections: List[str], options: List[str]) -> None:
        self.parser = parser

        self.sections = sections
        self.options = options

    def set_name(self, name: str) -> None:
        """Sets the name of the the used parsing template to the name of the discovered network manager."""
        self.name = name

    def get_config(self, path: TargetPath) -> Dict:
        """Create a generalized network config dictionary based on the provided Linux network configuration path.

        Returns:
            Generalized config based on the provided Linux network configuration path
        """
        fh = path

        if not fh.exists() or fh.is_dir():
            self.target.log.debug("Failed to get config file %s", fh)
            return None, None, None

        if self.name == "netplan":
            if PY_YAML:
                config = self.parser(stream=fh.open(), Loader=yaml.FullLoader)
            else:
                self.target.log.error("Failed to parse %s. Cannot import PyYAML", self.name)
        elif self.name == "wicked":
            # nasty workaround for namespaced XML without a namespace (xlmns) definitions
            # we have to replace the ":" for this with something else. which in this case is ___ (three underscores)
            pattern = compile(r"(?<=\n)\s+(<.+?>)")
            replace_match: Callable[[Match]] = lambda match: match.group(1).replace(":", "___")
            text = sub(pattern, replace_match, path.open("rt").read())

            xml = self.parser(file=StringIO(text))
            config = self._parse_xml_config(xml, self.sections, self.options)
        elif self.name == "interfaces":
            config = self._parse_text_config(("#"), " ", fh)
        elif isinstance(self.parser, ConfigParser):
            try:
                self.parser.read_string(fh.open("rt").read(), fh.name)
                config = self.parser._sections
            except MissingSectionHeaderError:
                # configparser does like config files without headers, so we inject a header to make it work.
                self.parser.read_string(f"[{self.name}]\n" + fh.open("rt").read(), fh.name)
                config = self.parser._sections
        return config

    def _parse_text_config(self, comments: str, delim: str, fh: TargetPath) -> Dict:
        """Internal function to parse a basic plain text based configuration file.

        Returns:
            Dictionary with a parsed plain text based Linux network manager configuration file.
        """
        config = defaultdict(dict)
        fh = fh.open("rt")

        for line in fh.readlines():
            if line.startswith(comments):
                continue
            else:
                for section in self.sections:
                    for option in self.options:
                        if option in line:
                            entry = line.split(delim, maxsplit=1)[1].rstrip()
                            config[section].update({option: entry})
        return dict(config)

    def _parse_xml_config(self, xml: ElementTree, sections: List, options: List) -> Dict:
        """Internal function to parse a xml based Linux network manager based configuration file.

        Returns:
            Dictionary parsed xml based Linux network manager based configuration file.
        """
        xml_dict = {}
        for section in sections:
            tag = section
            # as a side-effect of escaping the ":" value we have to escape values containing ":" here as well.
            section = section.replace(":", "___")
            for element in xml.findall(".//"):  # XPath glob for * on root
                if element.tag == section:
                    text = element.text.strip()
                    # a non-empty text field indicates that we are done searching for values
                    if text:
                        xml_dict[tag] = {tag: text}
                    else:
                        for option in options:
                            value = element.find(option)
                            if value is not None:
                                xml_dict[tag] = {option: value.text}
        return xml_dict


class Parser:
    def __init__(self, target: Target, template_name: str, config_globs: List[str], template: Template) -> None:
        self.target = target
        self.name = template_name
        self.template = template

        self.sections = self.template.sections
        self.options = self.template.options
        self.config_globs = config_globs

    def parse(self) -> Dict:
        """Returns a translated dictionary of network configuration properties.

        Returns:
            Dictionary containing network configuration properties for interface, dhcp, ips, gateways, dns, and netmask.
        """

        template = {
            "interface": set(),
            "dhcp": set(),
            "ips": set(),
            "gateway": set(),
            "dns": set(),
            "netmask": set(),
        }

        for path in self.expand_config_file_paths():
            config = self.template.get_config(path)

            for key, value in self.translate_network_config(config):
                template[key].add(value)
        return template

    def translate_network_config(self, config_dict: Dict) -> List[Tuple[str, Any]]:
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

    def expand_config_file_paths(self) -> List[TargetPath]:
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
            if any([value in option for value in translation_values]) and value:
                return translation_key
            else:
                continue

    def _get_option(self, config: Dict, option: Dict, section=None) -> Union[str, Callable]:
        """Internal function to get arbitrary options values from a parsed (non-translated) dictionary.

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
                elif isinstance(value, dict):
                    return self._get_option(value, option)


class NetworkManager:
    def __init__(self, name: str, detection_globs: Tuple[str], config_globs: Tuple[str]) -> None:
        self.target = None
        self.parser = None
        self.config = None

        self.name = name
        self.config_globs = (config_globs,) if isinstance(config_globs, str) else config_globs
        self.detection_globs = (detection_globs,) if isinstance(detection_globs, str) else detection_globs

    def detect(self, target=None) -> bool:
        """Detects what network manager(s) are active on the target

        Returns:
            Whether a certain network manager is detected on the target
        """
        for path in self.detection_globs:
            path = path.lstrip("/")

            if all([len(list(target.fs.path().glob(path)))]):
                target.log.debug("Found compatible network manager: %s", self.name)
                return True
            else:
                return False

    def register(self, target: Target, template: Template) -> bool:
        """Sets the detected parsing template and target the network manager.

        Returns:
            Whether the registration process was executed succesfully.
        """
        self.target = target
        self.parser = Parser(target, self.name, self.config_globs, template)
        self.parser.template.set_name(self.name)

        # Check if the unglobbed config files actually exists.
        # If not, nothing to parse. Thus we can skip this network manager.
        if self.parser.expand_config_file_paths():
            target.log.debug("Applying parsing template %s to network manager %s", self.parser.name, self.name)
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
            self.target.log.error("Network manager %s is not registered. Cannot parse config.")

    @property
    def interface(self) -> set:
        return self.config["interface"]

    @property
    def ips(self) -> set:
        return self.config["ips"]

    @property
    def dns(self) -> set:
        return self.config["dns"]

    @property
    def dhcp(self) -> bool:
        # we do some post-processing on dhcp values to get a final boolean verdict
        return self._dhcp()

    @property
    def gateway(self) -> set:
        return self.config["gateway"]

    @property
    def netmask(self) -> set:
        return self.config["netmask"]

    @property
    def registered(self) -> bool:
        if self.target and self.parser:
            return True
        else:
            return False

    def _dhcp(self) -> set:
        """Internal function to translate DHCP values to their boolean equivalent.

        Returns:
            Set of boolean values which indicate if DHCP is enabled for a interface.
        """
        # dhcp is either on or of per interface, so we require some extra post processing to give a accurate verdict
        translation_table = {
            True: ("yes", "dhcp", "auto"),
            False: ("no", "none", "static", "manual"),
        }

        translated_value = set()

        if self.config["dhcp"]:
            for dhcp_value in self.config["dhcp"]:
                if isinstance(dhcp_value, bool):
                    return translated_value.add(dhcp_value)
                else:
                    for key, value in translation_table.items():
                        if dhcp_value.lower() in value:
                            translated_value.add(key)
        else:
            translated_value.add(False)

        return translated_value

    def __repr__(self) -> str:
        return f"<NetworkManager {self.name}>"


class LinuxNetworkManager:
    def __init__(self, target: Target):
        self.managers = []
        self.target = target

    def discover(self):
        """Discover which defined network managers are active on the target.

        Registers the discovered network managers as active for parsing later on.
        """
        for manager in MANAGERS:
            if manager.detect(self.target):
                if manager.register(self.target, TEMPLATES[manager.name]):
                    self.managers.append(manager)

    def get_config_value(self, attr: str) -> List[set]:
        """Return the specified value from a network configuration option.

        Returns:
            List containing the values corrensponding to that configuration option.
        """
        values = []
        for manager in self.managers:
            manager.parse()
            value = getattr(manager, attr)
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
        ConfigParser(delimiters=("=", " "), comment_prefixes="#", dict_type=dict),
        ["netctl"],
        ["address", "gateway", "dns", "ip"],
    ),
    "netplan": Template(yaml.load, ["network"], ["addresses", "dhcp4", "gateway4"]),
    "NetworkManager": Template(
        ConfigParser(delimiters=("="), comment_prefixes="#", dict_type=dict), ["ipv4"], ["address1", "dns"]
    ),
    "systemd-networkd": Template(
        ConfigParser(delimiters=("="), comment_prefixes=("#", ";"), dict_type=dict),
        ["Network", "Match"],
        ["address", "dhcp", "dns", "name", "dhcpserver"],
    ),
    "wicked": Template(ElementTree, ["ipv4:static", "name"], ["./address/local", "name"]),
    "ifupdown": Template(
        ConfigParser(delimiters=("=", " "), comment_prefixes=("#"), dict_type=dict, strict=False),
        ["ifupdown"],
        ["ipaddr", "bootproto", "dns", "gateway", "name", "device", "dns1"],
    ),
    "interfaces": Template(None, ["interfaces"], ["iface", "address", "gateway"]),
}
