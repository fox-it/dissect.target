from __future__ import annotations

import random
from typing import TYPE_CHECKING

from flow.record import RecordDescriptor
from flow.record.base import Record, parse_def

from dissect.target.helpers.descriptor_extensions import (
    RecordDescriptorExtensionBase,
    TargetRecordDescriptorExtension,
)

if TYPE_CHECKING:
    from collections.abc import Sequence


class ExtendableRecordDescriptor(RecordDescriptor):
    def __init__(self, name: str, fields: Sequence[tuple[str, str]] | None = None):
        """A RecordDescriptor with default fields for dissect targets
        automatically added.
        """

        fields = fields or []
        prepend_default_fields = []
        append_default_fields = []
        extended_fields = []
        self.field_fillers = set()
        self.input_fields = set()
        self.target_fields = fields

        # all classes where we will look for `_default_fields` class
        # property and `_fill_default_fields` method
        classes = list(self.__class__.__bases__)

        for cls in classes:
            if hasattr(cls, "_default_fields"):
                if getattr(cls, "_prepend_fields", False):
                    prepend_default_fields.extend(cls._default_fields)
                else:
                    append_default_fields.extend(cls._default_fields)
            if hasattr(cls, "_fill_default_fields"):
                self.field_fillers.add(cls._fill_default_fields)
            if hasattr(cls, "_input_fields"):
                self.input_fields.update(cls._input_fields)

        if isinstance(fields, RecordDescriptor):
            # Clone fields
            fields = fields.get_field_tuples()
        elif fields is None:
            name, fields = parse_def(name)

        default_field_names = {field_name for _, field_name in prepend_default_fields + append_default_fields}
        extended_fields.extend(prepend_default_fields)

        for field_type, field_name in fields:
            if field_name in default_field_names:
                raise TypeError(f"Default field '{field_name}' is not allowed to be explicitly declared")
            extended_fields.append((field_type, field_name))

        extended_fields.extend(append_default_fields)

        super().__init__(name, fields=extended_fields)

    def __call__(self, *args, **kwargs) -> Record:
        """Generate a record.

        Default fields are prefilled if the _target keyword argument is
        supplied, any explicitly supplied (keyword) arguments for these fields
        are discarded.
        """
        if args:
            raise ValueError("Args are not allowed in ExtendableRecordDescriptor")

        for filler in self.field_fillers:
            kwargs = filler(self, kwargs)

        # cleanup input fields from record keyword arguments
        for input_field in self.input_fields:
            kwargs.pop(input_field, None)

        return super().__call__(*args, **kwargs)


def create_extended_descriptor(
    extensions: Sequence[RecordDescriptorExtensionBase], descriptor_class_name: str | None = None
) -> type[ExtendableRecordDescriptor]:
    class_name = descriptor_class_name or f"CustomExtendedRecordDescriptor{int(random.random() * 100000)}"
    # ExtendableRecordDescriptor must come first, since `ExtendableRecordDescriptor.__init__()` constructor
    # must be executed for extensions to work
    return type(class_name, (ExtendableRecordDescriptor, TargetRecordDescriptorExtension, *extensions), {})


TargetRecordDescriptor = create_extended_descriptor([])


def DynamicDescriptor(types: Sequence[str]) -> RecordDescriptor:
    """Returns a RecordDescriptor with the provided types.

    Plugins that yield records are required to provide their RecordDescriptor
    in the export decorator. However, some plugins dynamically create
    descriptors on the fly. The type of some fields can be known beforehand,
    though. This helper function allows plugins to provide a record
    descriptor that has at least those types, so that they can be used by
    things like an IOC checker, which would look for all plugins that yield
    records with a specific field type.
    """
    if not isinstance(types, (list, tuple)):
        raise TypeError("types must be a list or tuple")

    name = "_".join(types)
    return RecordDescriptor(name, [(t, t) for t in types])


ChildTargetRecord = TargetRecordDescriptor(
    "target/child",
    [
        ("string", "type"),
        ("path", "path"),
    ],
)


WindowsUserRecord = TargetRecordDescriptor(
    "windows/user",
    [
        ("string", "sid"),
        ("string", "name"),
        ("path", "home"),
    ],
)

COMMON_UNIX_FIELDS = [
    ("string", "name"),
    ("string", "passwd"),
    ("varint", "uid"),
    ("varint", "gid"),
    ("string", "gecos"),
    ("path", "home"),
    ("string", "shell"),
    ("string", "source"),
]

UnixUserRecord = TargetRecordDescriptor(
    "unix/user",
    COMMON_UNIX_FIELDS,
)

MacOSUserRecord = TargetRecordDescriptor(
    "macos/user",
    COMMON_UNIX_FIELDS,
)

IOSUserRecord = TargetRecordDescriptor(
    "ios/user",
    COMMON_UNIX_FIELDS,
)

EmptyRecord = RecordDescriptor(
    "empty",
    [],
)

COMMON_INTERFACE_ELEMENTS = [
    ("string", "name"),
    ("string", "type"),
    ("boolean", "enabled"),
    ("net.ipinterface[]", "cidr"),
    ("net.ipaddress[]", "gateway"),
    ("net.ipaddress[]", "dns"),
    ("string[]", "mac"),
    ("string", "source"),
]


UnixInterfaceRecord = TargetRecordDescriptor(
    "unix/network/interface",
    [
        *COMMON_INTERFACE_ELEMENTS,
        ("boolean", "dhcp_ipv4"),  # NetworkManager allows for dual-stack configurations.
        ("boolean", "dhcp_ipv6"),
        ("datetime", "last_connected"),
        ("varint[]", "vlan"),
        ("string", "configurator"),
    ],
)

WindowsInterfaceRecord = TargetRecordDescriptor(
    "windows/network/interface",
    [
        *COMMON_INTERFACE_ELEMENTS,
        ("varint", "metric"),
        ("stringlist", "search_domain"),
        ("datetime", "first_connected"),
        ("datetime", "last_connected"),
        ("boolean", "dhcp"),
        ("varint", "vlan"),
    ],
)

MacOSInterfaceRecord = TargetRecordDescriptor(
    "macos/network/interface",
    [
        *COMMON_INTERFACE_ELEMENTS,
        ("varint", "interface_service_order"),
        ("boolean", "dhcp"),
        ("varint", "vlan"),
    ],
)


COMMON_APPLICATION_FIELDS = [
    ("datetime", "ts_modified"),
    ("datetime", "ts_installed"),
    ("string", "name"),
    ("string", "version"),
    ("string", "author"),
    ("string", "type"),
    ("path", "path"),
]
