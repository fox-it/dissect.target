from dissect.target.plugin import Plugin, arg, export


class ExamplePlugin(Plugin):
    """Example plugin.

    This plugin serves as an example for new plugins. Use it as a guideline.

    Docstrings are used in help messages of plugins. Make sure to document
    your plugin and plugin functions. Use Google docstring format.
    https://sphinxcontrib-napoleon.readthedocs.io/en/latest/example_google.html

    Plugins can optionally be namespaced by specifying the __namespace__
    class attribute. Namespacing results in your plugin needing to be prefixed
    with this namespace when being called. For example, if your plugin has
    specified "test" as namespace and a function called "example", you must
    call your plugin with "test.example".

    Example:
        __namespace__ = 'test'

    Plugins can also specify one or more categories they belong to. They can do
    this by importing the Category enum from dissect.target.plugin and specifying
    them in a list in the __categories__ class attribute.

    Example:
        __categories__ = [Category.PERSISTENCE]

    The __init__ takes the target as only argument. Perform additional
    initialization here if necessary:

    def __init__(self, target):
        super().__init__(target)
    """

    def check_compatible(self):
        """Perform a compatibility check with the target.

        This function should return True or False on whether it's compatible
        with the current target (self.target). For example, check if a certain
        file exists.
        """
        return True

    @export
    @arg("--flag", action="store_true", help="optional example flag")
    def example(self, flag=False):
        """Example plugin function.

        Docstrings are used in help messages of plugins. Make sure to document
        your plugin and plugin functions. The first line must be a brief one
        sentence description of the plugin function.

        The @export decorator supports multiple arguments:
            property (bool): Whether this function should act like a property.
                Properties are implicitly cached.
            record (RecordDescriptor): The record descriptor this function yield,
                if any. If dynamic, use dissect.target.helpers.record.DynamicDescriptor.
            output (str): The output type of this function. Can be one of:
                - default: Single return value
                - record: Yields records. Implicit when record argument is given.
                - yield: Yields printable values.
                - none: No return value.

        Command line arguments can be added using the @arg decorator. Arguments
        to this decorator are directly forwarded to the add_argument function
        of argparse. (https://docs.python.org/2/library/argparse.html)
        Resulting arguments are passed to the function using kwargs.
        The keyword argument name must match the argparse argument name.
        """
        return f"Example plugin. Flag argument: {flag!r}"
