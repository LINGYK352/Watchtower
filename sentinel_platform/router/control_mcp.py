"""Dual-era Streamable HTTP, pre-provisioned Bearer authentication, guarded API delegation."""
from __future__ import annotations

import base64
import json

from flask import current_app, jsonify, request

from sentinel_platform.modules.workspace.control_sync.security import ControlSyncError

VERSIONS = ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"]
DOC_URI = "watchtower://control/operations"
TOOLS = [
    {"name": "watchtower_operations", "description": "List the business operations permitted by this Key and fetch their existing OpenAPI contracts.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
     "annotations": {"readOnlyHint": True}},
    {"name": "watchtower_request", "description": "Invoke one documented Watchtower business operation. Existing RBAC, activation, ownership and audit rules still apply. Read watchtower_operations first. Never use for user management, licensing, updates, or pairing confirmation.",
     "inputSchema": {"type": "object", "properties": {"method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"]},
                     "path": {"type": "string", "description": "An allowed /api/ path from the operations directory"},
                     "query": {"type": "object"}, "body": {"type": "object"}}, "required": ["method", "path"], "additionalProperties": False},
     "annotations": {"readOnlyHint": False, "destructiveHint": True}},
]


def _response(ident, result=None, error=None, status=200):
    body = {"jsonrpc": "2.0", "id": ident}
    body["error" if error is not None else "result"] = error if error is not None else result
    resp = jsonify(body)
    resp.status_code = status
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _header_value(value):
    if value and value.startswith("=?base64?") and value.endswith("?="):
        try:
            return base64.b64decode(value[9:-2], validate=True).decode("utf-8")
        except Exception:
            raise ControlSyncError("Invalid MCP header", 400) from None
    return value


def _contract(keys, key, app, user):
    operations = keys.operations(key, app)
    # Obtain the real parameter contracts through the same guarded Swagger route.
    with app.test_request_context("/api/swagger.json", environ_overrides={"watchtower.control_delegate": user}):
        response = app.full_dispatch_request()
        schema = response.get_json() if response.is_json and response.status_code == 200 else {}
    allowed = {(row["path"][4:], row["method"].lower()) for row in operations}
    paths = {path: {verb: value for verb, value in methods.items() if (path, verb) in allowed}
             for path, methods in schema.get("paths", {}).items()}
    return {"operations": operations, "contracts": {"paths": {p: v for p, v in paths.items() if v}, "definitions": schema.get("definitions", {})},
            "service": "Watchtower", "purpose": "Read this authenticated document to discover permitted business operations, then invoke them using watchtower_request. This is also suitable for an AI without an MCP SDK.",
            "operations_path": "/api/control_sync/watchtower_operations", "request_path": "/api/control_sync/watchtower_request", "mcp_path": "/api/control_sync/mcp",
            "http_request": {"method": "POST", "path": "/api/control_sync/watchtower_request", "headers": {"Authorization": "Bearer <CONTROL_KEY>", "Content-Type": "application/json"}, "json": {"method": "GET", "path": "/api/console/info"}},
            "authentication": "Authorization: Bearer <control-key>",
            "instructions": "Create keys in Workspace / Control & Sync. Keys expire and may be revoked. Only operations listed here are exposed. Pairing approvals require human administrators on both systems.",
            "example": {"name": "watchtower_request", "arguments": {"method": "GET", "path": "/api/console/info"}}}


def execute_operation(keys, key, user, arguments, app):
    if not isinstance(arguments, dict) or set(arguments) - {"method", "path", "query", "body"}:
        raise ControlSyncError("Invalid operation arguments")
    verb, path = keys.authorize_operation(key, arguments.get("method"), arguments.get("path"))
    query, body = arguments.get("query", {}), arguments.get("body")
    if not isinstance(query, dict) or len(query) > 50 or any(not isinstance(k, str) or not isinstance(v, (str, int, bool, float)) for k, v in query.items()) or (body is not None and not isinstance(body, dict)):
        raise ControlSyncError("Invalid query/body")
    peer_ip = request.remote_addr or ""
    with app.test_request_context(path, method=verb, query_string=query, json=body,
                                  environ_overrides={"watchtower.control_delegate": user, "REMOTE_ADDR": peer_ip}):
        response = app.full_dispatch_request()
        if not response.is_json:
            raise ControlSyncError("This operation returns a file or stream; use the documented Web UI")
        if len(response.get_data()) > 2 * 1024 * 1024:
            raise ControlSyncError("Result too large; add pagination")
        data = {"status": response.status_code, "response": response.get_json()}
    keys.record(key, "operation", method=verb, path=path, status=data["status"])
    return data


def handle_http_control(keys, operations=False):
    """A self-describing document and ordinary HTTP calls for AI clients without MCP support."""
    try:
        origin = request.headers.get("Origin")
        if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
            raise ControlSyncError("Invalid Origin", 403)
        auth = request.headers.get("Authorization", "")
        if operations and not auth:
            # Safe public onboarding explains the endpoint. The scoped catalog and
            # every operation still require an unexpired administrator-issued Key.
            return jsonify(service="Watchtower", title="Watchtower Operations / 瞭望塔接口与操作文档", authenticated=False,
                           instructions="把此文档地址和控制Key直接交给其他AI即可。先使用Authorization: Bearer <CONTROL_KEY>重新读取此地址获取授权接口目录，再通过watchtower_request调用。MCP客户端使用mcp端点。 / Give this document URL and a control Key to an AI. Fetch the scoped catalog with the Bearer Key, then call watchtower_request. MCP clients use the mcp endpoint.",
                           authentication="Authorization: Bearer <CONTROL_KEY>", operations_path="/api/control_sync/watchtower_operations",
                           request_path="/api/control_sync/watchtower_request", mcp_path="/api/control_sync/mcp",
                           request_example={"method": "GET", "path": "/api/console/info"})
        key, user = keys.authenticate(auth[7:] if auth.startswith("Bearer ") else "")
        app = current_app._get_current_object()
        if operations:
            result = _contract(keys, key, app, user)
        else:
            if not request.is_json or request.content_length is None or request.content_length > 1024 * 1024:
                raise ControlSyncError("An application/json object up to1MiB is required")
            result = execute_operation(keys, key, user, request.get_json(silent=True), app)
        response = jsonify(result)
        response.headers['Cache-Control'] = 'no-store'
        return response
    except ControlSyncError as exc:
        return jsonify(error=str(exc)), exc.status
    except Exception:
        from sentinel_platform.core import get_logger
        get_logger().exception('HTTP control request failed')
        return jsonify(error='Control service unavailable'), 503


def handle_mcp(keys):
    ident = None
    try:
        # Origin is optional for non-browser clients but must exactly match this origin when present.
        origin = request.headers.get("Origin")
        if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
            raise ControlSyncError("Invalid Origin", 403)
        auth = request.headers.get("Authorization", "")
        key, user = keys.authenticate(auth[7:] if auth.startswith("Bearer ") else "")
        if request.method != "POST":
            raise ControlSyncError("Use POST for Streamable HTTP", 405)
        if request.content_length is not None and request.content_length > 1024 * 1024:
            raise ControlSyncError("MCP request too large", 413)
        if not request.is_json:
            raise ControlSyncError("Content-Type must be application/json", 415)
        message = request.get_json(silent=True)
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            return _response(None, error={"code": -32600, "message": "Invalid JSON-RPC request"}, status=400)
        ident = message.get("id")
        if "id" in message and (isinstance(ident, bool) or not isinstance(ident, (str, int))):
            return _response(None, error={"code": -32600, "message": "Invalid request id"}, status=400)
        method = message["method"]
        params = message.get("params", {})
        if not isinstance(params, dict):
            raise ControlSyncError("Invalid params")
        version = request.headers.get("MCP-Protocol-Version", "")
        if method == "initialize" and not version:
            version = params.get("protocolVersion", "")
        version = version or "2025-03-26"
        modern = version == VERSIONS[0]
        if version not in VERSIONS:
            return _response(ident, error={"code": -32022, "message": "Unsupported protocol version", "data": {"supported": VERSIONS, "requested": version}}, status=400)
        if modern:
            meta = params.get("_meta", {})
            mismatch = not isinstance(meta, dict) or meta.get("io.modelcontextprotocol/protocolVersion") != version or request.headers.get("Mcp-Method") != method
            if method in ("tools/call", "resources/read", "prompts/get"):
                mismatch = mismatch or _header_value(request.headers.get("Mcp-Name")) != (params.get("name") or params.get("uri"))
            if mismatch:
                return _response(ident, error={"code": -32020, "message": "HeaderMismatch"}, status=400)
            client = meta.get("io.modelcontextprotocol/clientInfo")
            if not isinstance(client, dict) or not isinstance(client.get("name"), str) or not isinstance(client.get("version"), str) or not isinstance(meta.get("io.modelcontextprotocol/clientCapabilities"), dict):
                return _response(ident, error={"code": -32602, "message": "Required per-request client metadata is missing"}, status=400)
        if "id" not in message:
            if not modern and method == "notifications/initialized":
                return "", 202
            return _response(None, error={"code": -32601, "message": "Unsupported notification"}, status=400)
        app = current_app._get_current_object()
        info = {"name": "Watchtower Control", "version": "177"}
        capabilities = {"tools": {"listChanged": False}, "resources": {}}
        if method == "server/discover" and modern:
            result = {"supportedVersions": VERSIONS, "capabilities": capabilities, "_meta": {"io.modelcontextprotocol/serverInfo": info}, "instructions": "Read watchtower_operations before invoking business operations.", "ttlMs": 0, "cacheScope": "private"}
        elif method == "initialize" and not modern:
            result = {"protocolVersion": version, "capabilities": capabilities, "serverInfo": info, "instructions": "Read watchtower_operations first. Pre-provisioned Bearer Key required on every request."}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
            if modern:
                result.update(ttlMs=0, cacheScope="private")
        elif method == "resources/list":
            result = {"resources": [{"uri": DOC_URI, "name": "Watchtower operation manual", "mimeType": "application/json"}]}
            if modern:
                result.update(ttlMs=0, cacheScope="private")
        elif method in ("tools/call", "resources/read"):
            name = params.get("name") if method == "tools/call" else params.get("uri")
            arguments = params.get("arguments", {})
            if not isinstance(arguments, dict):
                raise ControlSyncError("Tool arguments must be an object")
            if name in ("watchtower_operations", DOC_URI):
                data = _contract(keys, key, app, user)
            elif name == "watchtower_request" and method == "tools/call":
                data = execute_operation(keys, key, user, arguments, app)
            else:
                return _response(ident, error={"code": -32602, "message": "Unknown tool/resource"})
            raw = json.dumps(data, ensure_ascii=False, default=str)
            if method == "resources/read":
                result = {"contents": [{"uri": DOC_URI, "mimeType": "application/json", "text": raw}]}
                if modern:
                    result.update(ttlMs=0, cacheScope="private")
            else:
                failed = data.get("status", 200) >= 400
                result = {"content": [{"type": "text", "text": raw}], "structuredContent": data, "isError": failed}
        else:
            return _response(ident, error={"code": -32601, "message": "Method not found"}, status=404 if modern else 200)
        if modern:
            result["resultType"] = "complete"
        return _response(ident, result=result)
    except ControlSyncError as exc:
        return _response(ident, error={"code": -32602 if exc.status == 400 else -32000, "message": str(exc)}, status=exc.status)
    except Exception:
        from sentinel_platform.core import get_logger
        get_logger().exception("control MCP request failed")
        return _response(ident, error={"code": -32603, "message": "Control service unavailable"}, status=503)
