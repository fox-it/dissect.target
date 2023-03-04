from typing import Iterator

from dissect.target.helpers.descriptor_extensions import (
    RegistryRecordDescriptorExtension,
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import (
    TargetRecordDescriptor,
    create_extended_descriptor,
)
from dissect.target.plugin import Plugin, arg, export, internal

ExampleRecordRecord = TargetRecordDescriptor(
    "example/descriptor",
    [
        ("string", "field_a"),
        ("string", "field_b"),
    ],
)

ExampleUserRegistryRecord = create_extended_descriptor(
    [RegistryRecordDescriptorExtension, UserRecordDescriptorExtension]
)(
    "example/registry/user",
    [
        ("datetime", "ts"),
    ],
)


class ExamplePlugin(Plugin):
    """Example plugin.

    This plugin serves as an example for new plugins. Use it as a guideline.

    Docstrings are used in help messages of plugins. Make sure to document
    your plugin and plugin functions. Use Google docstring format:

    https://sphinxcontrib-napoleon.readthedocs.io/en/latest/example_google.html

    Plugins can optionally be namespaced by specifying the ``__namespace__``
    class attribute. Namespacing results in your plugin needing to be prefixed
    with this namespace when being called. For example, if your plugin has
    specified ``test`` as namespace and a function called ``example``, you must
    call your plugin with ``test.example``::

        __namespace__ = "test"

    The ``__init__`` takes the target as only argument. Perform additional
    initialization here if necessary::

        def __init__(self, target):
            super().__init__(target)
    """

    __findable__ = False

    def check_compatible(self) -> bool:
        """Perform a compatibility check with the target.

        This function should return ``True`` or ``False`` on whether it's compatible
        with the current target (``self.target``). For example, check if a certain
        file exists. To provide a more detailed reason why your plugin is
        incompatible, you can also raise :class:`dissect.target.exceptions.UnsupportedPluginError`.
        """
        return True

    @export
    @arg("--flag", action="store_true", help="optional example flag")
    def example(self, flag: bool = False) -> str:
        """Example plugin function.

        Docstrings are used in help messages of plugins. Make sure to document
        your plugin and plugin functions. The first line must be a brief one
        sentence description of the plugin function.

        The ``@export`` decorator supports multiple arguments:
            property (bool): Whether this function should act like a property.
                Properties are implicitly cached.
            record (RecordDescriptor): The record descriptor this function yield,
                if any. If dynamic, use :class:`~dissect.target.helpers.record.DynamicDescriptor`.
            output (str): The output type of this function. Can be one of:
                - default: Single return value.
                - record: Yields records. Implicit when record argument is given.
                - yield: Yields printable values.
                - none: No return value.

        Command line arguments can be added using the ``@arg`` decorator. Arguments
        to this decorator are directly forwarded to the ``add_argument`` function
        of `argparse <https://docs.python.org/library/argparse.html>`_.
        Resulting arguments are passed to the function using kwargs.
        The keyword argument name must match the argparse argument name.
        """
        return f"Example plugin. Flag argument: {flag!r}"

    @export(record=ExampleRecordRecord)
    def example_record(self) -> Iterator[ExampleRecordRecord]:
        """Example plugin that generates records.

        To create a new plugin function that yields records, you must define a record descriptor
        and pass it to ``@export``. This will implicitly mark the output type as ``record``.
        """
        yield ExampleRecordRecord(
            field_a="example",
            field_b="record",
            _target=self.target,
        )

    @export(record=ExampleUserRegistryRecord)
    def example_user_registry_record(self) -> Iterator[ExampleUserRegistryRecord]:
        """Example plugin that generates records with registry key and user information.

        To include registry or user information in a record, you must create a new record descriptor using
        :func:`~dissect.target.helpers.record.create_extended_descriptor` with
        :class:`~dissect.target.helpers.descriptor_extensions.RegistryRecordDescriptorExtension` and/or
        :class:`~dissect.target.helpers.descriptor_extensions.UserRecordDescriptorExtension as extensions.
        """
        for key in self.target.registry.keys("HKCU\\SOFTWARE"):
            user = self.target.registry.get_user(key)
            yield ExampleUserRegistryRecord(
                ts=key.ts,
                _key=key,
                _user=user,
                _target=self.target,
            )

    @export(output="yield")
    def example_yield(self) -> Iterator[str]:
        """Example plugin that yields text lines.

        Setting ``output="yield"`` is useful for creating generators of text, such as human-readable timelines.
        """
        for i in range(10):
            yield f"Example line {i}"

    @export(output="none")
    def example_none(self) -> None:
        """Example plugin with no return value.

        Setting ``output="none"`` means you don't return a value. This is useful when you want to print something
        on your own, such as verbose information.
        """
        print("Example output with no return value.")

    @internal
    def example_internal(self) -> str:
        """Example internal plugin.

        Use the ``@internal`` plugin to mark your plugin as internal and hide it from the plugin overview.
        """
        return "Example internal plugin."
