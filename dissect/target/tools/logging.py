import logging
import sys
from typing import Any, Dict

import structlog


def custom_obj_renderer(
    logger: structlog.types.WrappedLogger,
    name: str,
    event_dict: structlog.types.EventDict,
) -> Dict[Any, str]:
    """Simple str() serialization for the event dict values for purely aesthetic reasons"""
    return {key: str(value) for key, value in event_dict.items()}


def render_stacktrace_only_in_debug_or_less(
    logger: structlog.types.WrappedLogger,
    name: str,
    event_dict: structlog.types.EventDict,
) -> Dict[Any, str]:
    """
    Render a stack trace of an exception only if `logger` is configured with `DEBUG` or lower level,
    otherwise render `str()` representation of an exception.
    """
    if event_dict.get("exc_info"):
        # If configured logging level is less permissive than DEBUG,
        # do not render full stack trace
        # https://docs.python.org/3/library/logging.html#logging-levels
        if logger.getEffectiveLevel() > logging.DEBUG:
            event_dict.pop("exc_info")
            _, exc, _ = sys.exc_info()
            event_dict["exc"] = str(exc)
    return event_dict


def configure_logging(verbose_value: int, be_quiet: bool, as_plain_text: bool = True):
    """Configure logging level for `dissect` root logger.

    By default, if `verbose_value` is not set (equals 0) and `be_quiet` is False,
    set logging level for `dissect` root logger to `WARNING`.

    If `be_quiet` is set to True, logging level is set to the least noisy `CRITICAL` level.
    """

    renderer = (
        structlog.dev.ConsoleRenderer(colors=True, pad_event=10)
        if as_plain_text
        else structlog.processors.JSONRenderer(sort_keys=True)
    )

    attr_processors = [
        # Add the name of the logger to event dict.
        structlog.stdlib.add_logger_name,
        # Add log level to event dict.
        structlog.stdlib.add_log_level,
        # Add a timestamp in ISO 8601 format.
        structlog.processors.TimeStamper(fmt="iso"),
    ]

    structlog.configure(
        processors=(
            [
                # If log level is too low, abort pipeline and throw away log entry.
                structlog.stdlib.filter_by_level,
            ]
            + attr_processors
            + [
                # Perform %-style formatting.
                structlog.stdlib.PositionalArgumentsFormatter(),
                # If the "stack_info" key in the event dict is true, remove it and
                # render the current stack trace in the "stack" key.
                structlog.processors.StackInfoRenderer(),
                custom_obj_renderer,
                render_stacktrace_only_in_debug_or_less,
                # Wrapping is needed in order to use formatter down the line
                structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
            ]
        ),
        # `wrapper_class` is the bound logger that you get back from
        # get_logger(). This one imitates the API of `logging.Logger`.
        wrapper_class=structlog.stdlib.BoundLogger,
        # `logger_factory` is used to create wrapped loggers that are used for
        # OUTPUT. This one returns a `logging.Logger`.
        logger_factory=structlog.stdlib.LoggerFactory(),
        # Effectively freeze configuration after creating the first bound
        # logger.
        cache_logger_on_first_use=True,
    )

    # warnings issued by the ``warnings`` module will be
    # redirected to the ``py.warnings`` logger
    logging.captureWarnings(True)

    dissect_logger = logging.getLogger("dissect")

    if be_quiet:
        dissect_logger.setLevel(level=logging.CRITICAL)
    elif verbose_value == 0:
        dissect_logger.setLevel(level=logging.WARNING)
    elif verbose_value == 1:
        dissect_logger.setLevel(level=logging.INFO)
    elif verbose_value > 1:
        dissect_logger.setLevel(level=logging.DEBUG)
    else:
        pass

    formatter = structlog.stdlib.ProcessorFormatter(processor=renderer, foreign_pre_chain=attr_processors)

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    # set handler on a root logger
    logging.getLogger().handlers = [handler]
