from typing import Iterator
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export


ExampleRecordDescriptor = TargetRecordDescriptor(
    "example/descriptor",
    [
        ("string", "field_a"),
        ("string", "field_b"),
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

    @export(record=ExampleRecordDescriptor)
    def example_record(self) -> Iterator[ExampleRecordDescriptor]:
        """Example plugin that generates records.

        To create a new plugin function that yields records, you must define a record descriptor
        and pass it to ``@export``. This will implicitly mark the output type as ``record``.
        """
        yield ExampleRecordDescriptor(
            field_a="example",
            field_b="record",
            _target=self.target,
        )
