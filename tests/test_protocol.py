"""Verify packet-routed scanner decisions and credential rejection with the SDK client."""

import asyncio
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def test_stdio_discovery_and_gate():
    async def exercise():
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "sentinel.cli", "mcp"]
        )
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer) as client:
                await client.initialize()
                tools = await client.list_tools()
                assert len(tools.tools) == 8
                for tool in tools.tools:
                    assert (
                        tool.annotations.readOnlyHint
                        and not tool.annotations.destructiveHint
                    )
                report = await client.call_tool(
                    "sentinel_discover",
                    {
                        "host": "workbuddy",
                        "observations": [{"name": "qq-mail", "kind": "configured"}],
                    },
                )
                assert report.structuredContent["services"][0]["service"] == "qqmail"
                denied = await client.call_tool(
                    "sentinel_review_tool_call",
                    {
                        "origin": "external_content",
                        "operation": "execute",
                        "allowed_operations": ["read"],
                    },
                )
                assert denied.structuredContent["disposition"] == "stop"
                failure = await client.call_tool(
                    "sentinel_discover", {"host": "unknown_host", "observations": []}
                )
                assert failure.isError
                status = await client.call_tool("sentinel_get_status", {})
                assert not status.isError

    asyncio.run(exercise())
