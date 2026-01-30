#!/usr/bin/env python
from __future__ import annotations

import argparse
import asyncio
import logging
import re
from itertools import islice
from typing import TYPE_CHECKING, Any

try:
    import mcpo.main
    from mcp.server.fastmcp import FastMCP
    HAS_MCP = True
except ImportError:
    HAS_MCP = False

if TYPE_CHECKING:
    from collections.abc import Generator

    from flow.record import RecordDescriptor

    from dissect.target.target import Target

from dissect.target.exceptions import TargetError
from dissect.target.helpers.logging import get_logger
from dissect.target.plugin import FunctionDescriptor, find_functions
from dissect.target.tools.utils.cli import (
    catch_sigpipe,
    configure_generic_arguments,
    execute_function_on_target,
    open_targets,
    process_generic_arguments,
)

log = get_logger(__name__)
logging.lastResort = None
logging.raiseExceptions = False

# Global list of targets
targets: list[Target] = []
mcp = FastMCP("target-mcp", json_response=True, stateless_http=True, streamable_http_path="/mcp")

# Note that I am not a prompt engineering expert, so this probably be improved significantly.
EXAMPLE_PROMPT = """# Digital Forensic Investigation Assistant

You are a digital forensic investigator using the Dissect framework to analyze forensic targets. Your role is to help users investigate systems by running plugins and analyzing their output.

## Investigation Workflow

For each user question, follow this structured approach:

### 1. Target Discovery
- First, check the available targets
- If user specifies a Target, validate it exists

### 2. Question Clarification
- Understand exactly what information the user needs
- Ask for clarification if the request is vague
- Identify the type of artifacts or data required

### 3. Plugin Selection
- Obtain the available plugins for the Target
- Review plugin names & descriptions to identify relevant ones
- Select plugins that match the investigation objective
- For each selected plugin, get the output fields

### 4. Output Planning
- Determine whether the users asks something generic or already gives specific filter criteria
- If specific filter criteria are provided by the user, create filters accordingly
- Filters are in the form of a dict where keys are output field names and values are regex strings to match

### 5. Plugin Execution
- Run selected plugins on the Target, optionally with the filters defined previously
- Process results systematically (max 50 records per plugin)

### 6. Analysis & Response
- Analyze only the actual plugin output
- Summarize findings while preserving important details
- Base conclusions strictly on evidence from plugin results

## Critical Rules

**EVIDENCE INTEGRITY**
- NEVER fabricate or assume data not present in plugin output
- Only report facts directly supported by plugin results
- Use standard ASCII characters for target names (no Unicode variants)

**Methodology**
- Always show your investigation steps to the user
- Be transparent about which plugins you're using and why
- Explain any limitations or gaps in available data

## Getting Started

1. Greet the user professionally
2. List available targets
3. Ask what they would like to investigate
4. Follow the workflow above for each question

Ready to begin forensic investigation."""  # noqa: E501

def name_to_target(target_name: str) -> tuple[Target, str]:
    """Helper function to get a target by name. Returns some context about the selection method."""

    # Sometimes, LLM's use these unicode hyphen characters instead of the standard ASCII hyphen-minus
    normalized_target_name = target_name.replace("‑", "-").replace("–", "-").replace("—", "-")  # noqa: RUF001

    for target in targets:
        if target.name == normalized_target_name:
            return target, "Target selected by exact match.\n"
        if normalized_target_name in target.name:
            return target, f"Target selected by substring match: '{normalized_target_name}' in '{target.name}'.\n"

    raise TargetError(f"Target '{target_name}' not found")


def filter_results(results: Generator[Any], filters: dict[str, str]) -> Generator[Any]:
    """Filter results based on a filter string."""
    for result in results:
        hits = {k+v: False for k, v in filters.items()}
        for field, filter_str in filters.items():
            value = str(getattr(result, field, ""))
            if re.search(filter_str, value, re.IGNORECASE):
                hits[field+filter_str] = True
                break

        if all(hits.values()):
            yield result

def get_functions_summary(functions: list[FunctionDescriptor]) -> str:
    """Return a summary of functions with docstring info as a string"""
    result = f"\nSummary of {len(functions)} functions:\n"
    result += "-" * 80 + "\n"

    for func_desc in functions:
        try:
            func = func_desc.func
            docstring = func.__doc__
            doc_preview = "No docstring"

            if docstring:
                first_line = docstring.strip().split("\n")[0]
                doc_preview = first_line[:60] + "..." if len(first_line) > 60 else first_line

            result += f"{func_desc.path} | {doc_preview}\n"

        except Exception as e:
            result += f"{func_desc.path} | Error: {e}\n"
    return result


@mcp.tool()
def get_targets(limit: int = 0) -> str:
    """Get the available Targets."""
    log.critical("Getting available targets")
    return ", ".join(target.name for target in targets[:limit if limit > 0 else None])


@mcp.tool()
def get_record_output_fields_for_plugin(plugin_path: str) -> str:
    """
    Return the output fields for a plugin that returns records.
    Can be used to determine to which fields filters could be applied.
    """
    functions, _ = find_functions(plugin_path)
    if not functions:
        return f"No plugin found matching '{plugin_path}'"

    if len(functions) > 1:
        return f"Multiple plugins found matching '{plugin_path}',"
    "please be more specific and enter the full plugin path."

    func_desc = functions[0]
    log.critical("Getting output fields for plugin '%s'", func_desc.path)
    output_records: RecordDescriptor | list[RecordDescriptor] = func_desc.record
    if len(output_records) <= 0:
        return f"Plugin '{func_desc.path}' does not return any records."
    if len(output_records) == 1:
        return f"Output fields for plugin '{func_desc.path}': {', '.join(output_records.get_all_fields().keys())}"
    result = f"Plugin '{func_desc.path}' has multiple output RecordDescriptors:\n"
    for rd in output_records:
        result += f"RecordDescriptor {rd.name}: {', '.join(rd.get_all_fields().keys())}\n"
    return result


@mcp.tool()
def run_plugin_on_target(target_name: str, plugin_path: str, filters: None | dict[str, str] = None) -> str:
    """
    Run a specific plugin on a Target and return the result as a string.
    Requires a plugin_path that can be obtained via get_target_plugins. Filters can be passed as a dict.
    """
    target, context = name_to_target(target_name)

    functions, _ = find_functions(plugin_path, target)
    if not functions:
        return f"No plugin found matching '{plugin_path}' on target '{target_name}'"

    if len(functions) > 1:
        return f"Multiple plugins found matching '{plugin_path}' on target '{target_name}',"
    "please be more specific and enter the full plugin path."

    func_desc = functions[0]
    log.critical("Running plugin '%s' on target '%s' with filters: %s", func_desc.path, target.name, filters)

    output_type, results = execute_function_on_target(target, func_desc)

    # Optionally, apply a filter
    results = filter_results(results, filters) if filters else results

    if output_type == "default":
        context += f"Result: {results}\n"
    elif output_type == "record":
        context += "Showing first 50 records only:\n"
        for result in islice(results, 50):
            context += f"{result}\n"

    return context

@mcp.tool()
def get_target_plugins(target_name: str) -> str:
    """
    Get a summary of the available plugins for a Target. Based on the plugin name and summary,
    we can determine whether we have any plugins available for the information that the user is requesting.
    """
    target, context = name_to_target(target_name)
    fuction_descriptors, _ = find_functions("*", target)
    log.critical("Found %d plugins for target '%s'", len(fuction_descriptors), target.name)
    return context + get_functions_summary(fuction_descriptors)


@catch_sigpipe
async def _main() -> int:
    if not HAS_MCP:
        raise ImportError(
            "Required dependencies 'mcpo' and 'mcp' are missing, install with 'pip install dissect.target[mcp]'"
        )

    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="target-mcp",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
    )
    parser.add_argument("targets", metavar="TARGETS", nargs="*", help="Targets to allow the MCP server to connect to")
    parser.add_argument("-op", "--openapiport", action="store", type=int, default=8000, help="the OpenAPI server port")
    parser.add_argument("-mp", "--mcpport", action="store", type=int, default=8001, help="the MCP server port")
    parser.add_argument("--example-prompt", action="store_true", help="print an example prompt and exit")
    parser.add_argument(
        "--host", action="store", default="127.0.0.1", help="the host to bind to for connections"
    )
    parser.add_argument(
        "--path", action="store", default="mcp", help="the MCP server path"
    )
    configure_generic_arguments(parser)

    args, _ = parser.parse_known_args()

    if not args.targets:
        parser.error("too few arguments")

    process_generic_arguments(parser, args)

    if args.example_prompt:
        print(EXAMPLE_PROMPT)
        return 0

    # Override MCP settings
    mcp.settings.host = args.host
    mcp.settings.port = args.mcpport
    mcp_endpoint = f"http://{args.host}:{args.mcpport}/{args.path}"

    # Pre-load all targets in a global list, so they are available for MCP
    global targets

    try:
        targets = list(open_targets(args))

    except TargetError as e:
        log.exception()
        log.debug("", exc_info=e)
        return 1


    log.critical("MCP server running at %s", mcp_endpoint)
    log.critical("OpenAPI server running at http://%s:%d", args.host, args.openapiport)
    log.critical("For use in Open WebUI: Settings -> External Tools -> Add Connection and fill in the OpenAPI URL, "
             "without authentication. Optionally, copy the example prompt (target-mcp --example-prompt) "
             "to Settings -> System Prompt.")
    log.critical("\nTargets loaded (%d): %s\n\n", len(targets), [t.name for t in targets])

    # Create two asyncio tasks: one for the MCP server, one for the OpenAPI server
    mcp_task = asyncio.create_task(mcp.run_streamable_http_async())
    mcpo_task = asyncio.create_task(
        mcpo.main.run(
            args.host,
            args.openapiport,
            server_type="streamable-http",
            server_command=[mcp_endpoint],
        )
    )
    # Wait for either task to complete (which should be never, unless interrupted)
    # When interrupted, cancel both tasks
    try:
        _, pending = await asyncio.wait([mcpo_task, mcp_task], return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
    except KeyboardInterrupt:
            mcpo_task.cancel()
            mcp_task.cancel()


def main() -> int:
    return asyncio.run(_main())
