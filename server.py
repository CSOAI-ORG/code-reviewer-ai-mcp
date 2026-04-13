#!/usr/bin/env python3
"""code-reviewer-ai-mcp — Review code for bugs and improvements."""
import asyncio, json
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.server.models import InitializationOptions
from mcp.types import Tool, TextContent
import mcp.types as types

server = Server("code-reviewer-ai-mcp")

@server.list_tools()
async def list_tools():
    return [Tool(name="run", description="Review code for bugs and improvements.", inputSchema={"type":"object","properties":{"input":{"type":"string"}},"required":["input"]})]

@server.call_tool()
async def call_tool(name, arguments=None):
    inp = (arguments or {}).get("input", "")
    result = {"output": f"Processed: {inp}"}
    return [TextContent(type="text", text=json.dumps(result, indent=2))]

async def main():
    async with stdio_server(server._read_stream, server._write_stream) as (rs, ws):
        await server.run(rs, ws, InitializationOptions(server_name="code-reviewer-ai-mcp", server_version="0.1.0", capabilities=server.get_capabilities()))

if __name__ == "__main__":
    asyncio.run(main())
