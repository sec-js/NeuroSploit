"""
NeuroSploit v3 - MCP Server Management API

CRUD for Model Context Protocol server connections.
Persists to config/config.json mcp_servers section.
"""
import json
import asyncio
from pathlib import Path
from typing import Optional, List, Dict
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()

CONFIG_PATH = Path(__file__).parent.parent.parent.parent / "config" / "config.json"

BUILTIN_SERVER = "neurosploit_tools"


# --- Schemas ---

class MCPServerCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Unique server identifier")
    transport: str = Field("stdio", description="Transport type: stdio or sse")
    command: Optional[str] = Field(None, description="Command for stdio transport")
    args: Optional[List[str]] = Field(None, description="Args for stdio transport")
    url: Optional[str] = Field(None, description="URL for sse transport")
    env: Optional[Dict[str, str]] = Field(None, description="Environment variables")
    description: str = Field("", description="Server description")
    enabled: bool = Field(True, description="Whether server is enabled")


class MCPServerUpdate(BaseModel):
    transport: Optional[str] = None
    command: Optional[str] = None
    args: Optional[List[str]] = None
    url: Optional[str] = None
    env: Optional[Dict[str, str]] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None


class MCPServerResponse(BaseModel):
    name: str
    transport: str
    command: Optional[str] = None
    args: Optional[List[str]] = None
    url: Optional[str] = None
    env: Optional[Dict[str, str]] = None
    description: str = ""
    enabled: bool = True
    is_builtin: bool = False


class MCPToolResponse(BaseModel):
    name: str
    description: str
    server_name: str


# --- Config helpers ---

def _read_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    with open(CONFIG_PATH) as f:
        return json.load(f)


def _write_config(config: dict):
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=4)


def _get_mcp_servers(config: dict) -> dict:
    return config.get("mcp_servers", {})


def _server_to_response(name: str, server: dict) -> MCPServerResponse:
    return MCPServerResponse(
        name=name,
        transport=server.get("transport", "stdio"),
        command=server.get("command"),
        args=server.get("args"),
        url=server.get("url"),
        env=server.get("env"),
        description=server.get("description", ""),
        enabled=server.get("enabled", True),
        is_builtin=(name == BUILTIN_SERVER),
    )


# --- Endpoints ---

@router.get("/servers", response_model=List[MCPServerResponse])
async def list_servers():
    """List all configured MCP servers."""
    config = _read_config()
    servers = _get_mcp_servers(config)
    return [_server_to_response(name, srv) for name, srv in servers.items()]


@router.get("/servers/{name}", response_model=MCPServerResponse)
async def get_server(name: str):
    """Get a specific MCP server configuration."""
    config = _read_config()
    servers = _get_mcp_servers(config)
    if name not in servers:
        raise HTTPException(404, f"MCP server '{name}' not found")
    return _server_to_response(name, servers[name])


@router.post("/servers", response_model=MCPServerResponse)
async def create_server(body: MCPServerCreate):
    """Add a new MCP server configuration."""
    config = _read_config()
    if "mcp_servers" not in config:
        config["mcp_servers"] = {}

    servers = config["mcp_servers"]
    if body.name in servers:
        raise HTTPException(409, f"Server '{body.name}' already exists")

    # Validate transport-specific fields
    if body.transport == "stdio" and not body.command:
        raise HTTPException(400, "stdio transport requires 'command' field")
    if body.transport == "sse" and not body.url:
        raise HTTPException(400, "sse transport requires 'url' field")

    server_config = {
        "transport": body.transport,
        "description": body.description,
        "enabled": body.enabled,
    }
    if body.command:
        server_config["command"] = body.command
    if body.args:
        server_config["args"] = body.args
    if body.url:
        server_config["url"] = body.url
    if body.env:
        server_config["env"] = body.env

    servers[body.name] = server_config
    _write_config(config)

    return _server_to_response(body.name, server_config)


@router.put("/servers/{name}", response_model=MCPServerResponse)
async def update_server(name: str, body: MCPServerUpdate):
    """Update an MCP server configuration."""
    config = _read_config()
    servers = _get_mcp_servers(config)

    if name not in servers:
        raise HTTPException(404, f"MCP server '{name}' not found")

    srv = servers[name]
    if body.transport is not None:
        srv["transport"] = body.transport
    if body.command is not None:
        srv["command"] = body.command
    if body.args is not None:
        srv["args"] = body.args
    if body.url is not None:
        srv["url"] = body.url
    if body.env is not None:
        srv["env"] = body.env
    if body.description is not None:
        srv["description"] = body.description
    if body.enabled is not None:
        srv["enabled"] = body.enabled

    _write_config(config)
    return _server_to_response(name, srv)


@router.delete("/servers/{name}")
async def delete_server(name: str):
    """Delete an MCP server configuration."""
    if name == BUILTIN_SERVER:
        raise HTTPException(403, f"Cannot delete built-in server '{BUILTIN_SERVER}'")

    config = _read_config()
    servers = _get_mcp_servers(config)

    if name not in servers:
        raise HTTPException(404, f"MCP server '{name}' not found")

    del servers[name]
    _write_config(config)
    return {"message": f"Server '{name}' deleted"}


@router.post("/servers/{name}/toggle", response_model=MCPServerResponse)
async def toggle_server(name: str):
    """Toggle a server's enabled state."""
    config = _read_config()
    servers = _get_mcp_servers(config)

    if name not in servers:
        raise HTTPException(404, f"MCP server '{name}' not found")

    srv = servers[name]
    srv["enabled"] = not srv.get("enabled", True)
    _write_config(config)
    return _server_to_response(name, srv)


@router.post("/servers/{name}/test")
async def test_server_connection(name: str):
    """Test connection to an MCP server."""
    config = _read_config()
    servers = _get_mcp_servers(config)

    if name not in servers:
        raise HTTPException(404, f"MCP server '{name}' not found")

    srv = servers[name]
    transport = srv.get("transport", "stdio")

    try:
        if transport == "sse":
            # Test SSE endpoint
            import aiohttp
            url = srv.get("url", "")
            if not url:
                return {"success": False, "error": "No URL configured", "tools_count": 0}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status < 400:
                        return {"success": True, "message": f"SSE endpoint reachable (HTTP {resp.status})", "tools_count": 0}
                    return {"success": False, "error": f"HTTP {resp.status}", "tools_count": 0}

        elif transport == "stdio":
            # Test stdio by checking command exists
            import shutil
            command = srv.get("command", "")
            if not command:
                return {"success": False, "error": "No command configured", "tools_count": 0}

            if shutil.which(command):
                return {"success": True, "message": f"Command '{command}' found in PATH", "tools_count": 0}
            else:
                return {"success": False, "error": f"Command '{command}' not found in PATH", "tools_count": 0}

    except asyncio.TimeoutError:
        return {"success": False, "error": "Connection timed out (5s)", "tools_count": 0}
    except Exception as e:
        return {"success": False, "error": str(e), "tools_count": 0}


@router.get("/servers/{name}/tools", response_model=List[MCPToolResponse])
async def list_server_tools(name: str):
    """List available tools from an MCP server.
    
    For the built-in server, returns tools from the registry.
    For external servers, attempts to connect and query.
    """
    config = _read_config()
    servers = _get_mcp_servers(config)

    if name not in servers:
        raise HTTPException(404, f"MCP server '{name}' not found")

    # For builtin server, return tools from the MCP server module
    if name == BUILTIN_SERVER:
        try:
            from core.mcp_server import TOOLS
            return [
                MCPToolResponse(
                    name=t["name"],
                    description=t.get("description", ""),
                    server_name=name,
                )
                for t in TOOLS
            ]
        except ImportError:
            return []

    # For external servers, try to connect via MCPToolClient
    try:
        from core.mcp_client import MCPToolClient
        
        # Build minimal config for this single server
        client_config = {
            "mcp_servers": {
                "enabled": True,
                "servers": {name: servers[name]}
            }
        }
        client = MCPToolClient(client_config)
        
        connected = await asyncio.wait_for(client.connect(name), timeout=10)
        if not connected:
            raise HTTPException(502, f"Failed to connect to MCP server '{name}'")
        
        tools_dict = await client.list_tools(name)
        tool_list = tools_dict.get(name, [])
        
        await client.disconnect_all()
        
        return [
            MCPToolResponse(
                name=t.get("name", ""),
                description=t.get("description", ""),
                server_name=name,
            )
            for t in tool_list
        ]
    except ImportError:
        raise HTTPException(501, "MCP client library not installed")
    except asyncio.TimeoutError:
        raise HTTPException(504, "Connection to MCP server timed out (10s)")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"Failed to list tools: {str(e)}")
