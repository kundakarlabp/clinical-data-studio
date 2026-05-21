from __future__ import annotations

import json
from typing import Any

from .schemas import MCP_PROTOCOL_VERSION, tool_descriptors


def _rpc_result(request_id: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _rpc_error(request_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _tool_content(payload: dict) -> dict:
    return {
        "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, sort_keys=True)}],
        "structuredContent": payload,
    }


def handle_mcp_http(app, conn, service, method: str) -> None:
    if method == "GET":
        app.send_json({"service": "Clinical Data Studio MCP", "transport": "streamable-http", "read_only": True, "endpoint": "/mcp"})
        return
    if method != "POST":
        app.send_json(_rpc_error(None, -32600, "Unsupported MCP method"), 405)
        return
    try:
        body = app.body()
    except Exception:
        app.send_json(_rpc_error(None, -32700, "Invalid JSON body"), 400)
        return
    request_id = body.get("id")
    rpc_method = str(body.get("method", ""))
    params = body.get("params") or {}
    if body.get("jsonrpc") != "2.0" or not rpc_method:
        app.send_json(_rpc_error(request_id, -32600, "Malformed JSON-RPC request"), 400)
        return
    auth_header = app.headers.get("authorization", "")
    token = auth_header.removeprefix("Bearer ").strip() if auth_header.startswith("Bearer ") else ""
    context = {
        "ip_address": app.client_address[0] if app.client_address else "",
        "user_agent": app.headers.get("user-agent", ""),
    }
    try:
        if rpc_method == "initialize":
            service.authenticate(conn, token, context)
            result = {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "Clinical Data Studio", "version": "0.1"},
            }
            app.send_json(_rpc_result(request_id, result))
            return
        if rpc_method == "tools/list":
            service.authenticate(conn, token, context)
            app.send_json(_rpc_result(request_id, {"tools": tool_descriptors()}))
            return
        if rpc_method == "tools/call":
            name = str(params.get("name", ""))
            arguments = params.get("arguments") or {}
            result = service.call_tool(conn, token, name, arguments, context)
            app.send_json(_rpc_result(request_id, _tool_content(result)))
            return
        app.send_json(_rpc_error(request_id, -32601, "Unknown MCP method"), 404)
    except PermissionError as exc:
        app.send_json(_rpc_error(request_id, -32001, str(exc)), 403)
    except ValueError as exc:
        app.send_json(_rpc_error(request_id, -32602, str(exc)), 400)
    except Exception:
        app.send_json(_rpc_error(request_id, -32603, "MCP request failed safely"), 500)

