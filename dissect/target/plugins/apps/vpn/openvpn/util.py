from __future__ import annotations

import io
from typing import TYPE_CHECKING

from dissect.target.exceptions import ConfigurationParsingError
from dissect.target.helpers.configutil import Default, ListUnwrapper, _update_dictionary

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target


class OpenVPNParser(Default):
    def __init__(self, *args, boolean_fields: dict | None = None, **kwargs):
        self.boolean_field_names = {field.name.replace("_", "-") for field in boolean_fields} if boolean_fields else {}

        super().__init__(*args, separator=(r"\s",), collapse=["key", "ca", "cert"], **kwargs)

    def parse_file(self, fh: io.TextIOBase) -> None:
        root = {}
        iterator = self.line_reader(fh)
        for line in iterator:
            if line.startswith("<"):
                key = line.strip().strip("<>")
                value = self._read_blob(iterator)
                _update_dictionary(root, key, value)
                continue

            self._parse_line(root, line)

        self.parsed_data = ListUnwrapper.unwrap(root)

    def _read_blob(self, lines: Iterator[str]) -> str | list[dict]:
        """Read the whole section between ``<data></data>`` sections."""
        output = ""
        with io.StringIO() as buffer:
            for line in lines:
                if "</" in line:
                    break

                buffer.write(line)
            output = buffer.getvalue()

        # Check for connection profile blocks
        if not output.startswith("-----"):
            profile_dict = {}
            for line in output.splitlines():
                self._parse_line(profile_dict, line)

            # We put it as a list as _update_dictionary appends data in a list.
            output = [profile_dict]

        return output

    def _parse_line(self, root: dict, line: str) -> None:
        key, *value = self.SEPARATOR.split(line, 1)
        value = value[0].strip() if value else ""

        if key in self.boolean_field_names:
            value = True

        # Format of tls-auth is `tls-auth '/path/to/a ta.key' <NUM>`, we remove the number
        if key == "tls-auth":
            value, _, _ = value.rpartition(" ")

        # Unquote
        value = value.strip("'\"")

        _update_dictionary(root, key, value)


def parse_config(target: Target, parser: OpenVPNParser, config_path: Path) -> dict | None:
    with config_path.open("rt") as file:
        try:
            parser.parse_file(file)
        except ConfigurationParsingError as e:
            target.log.info("An issue occurred during parsing of %s, continuing", config_path)
            target.log.debug("", exc_info=e)
            return None

    return parser.parsed_data
