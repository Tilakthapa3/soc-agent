"""SOC Agent step 2: MCP server.

Exposes the read-only SOC Agent tools over the Model Context Protocol
(JSON-RPC 2.0, newline-delimited, over stdio), so an MCP client can
give an AI safe, read-only access to real security inputs instead of
the built-in guidance table in step 1.

Tools (all read-only; none of them acts, writes, or runs commands):
  - read_incident_file: read one JSON incident file (CyberBeep-style)
  - read_finding_file:  read one JSON scan-finding file (nmap-style)
  - lookup_guidance:    MITRE guidance for an incident type / service
  - triage_item:        triage one incident/finding object (mock model,
                        offline) and return the structured verdict

Standard library only. Run:  python3 mcp_server.py
"""

import json
import sys

import soc_agent

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "soc-agent", "version": "0.2.0"}

TOOLS = [
    {
        "name": "read_incident_file",
        "description": "Read one JSON incident file (CyberBeep-style) "
                       "and return its summary. Read-only.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string",
                         "description": "Path to a JSON incident file."}
            },
            "required": ["path"],
        },
    },
    {
        "name": "read_finding_file",
        "description": "Read one JSON scan-finding file (nmap-style) "
                       "and return its summary. Read-only.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string",
                         "description": "Path to a JSON finding file."}
            },
            "required": ["path"],
        },
    },
    {
        "name": "lookup_guidance",
        "description": "MITRE guidance (technique, meaning, what to "
                       "check next, suggested actions) for an incident "
                       "type or service, e.g. login_after_brute_force "
                       "or telnet. Read-only.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string",
                        "description": "Incident type or service name."}
            },
            "required": ["key"],
        },
    },
    {
        "name": "triage_item",
        "description": "Triage one incident or finding object and "
                       "return the structured verdict (verdict, "
                       "severity, cause, actions, confidence, MITRE). "
                       "Read-only; uses the offline mock model.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "item": {"type": "object",
                         "description": "Incident or finding object."}
            },
            "required": ["item"],
        },
    },
]


def _read_json_file(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def call_tool(name, arguments):
    """Dispatch one tool call. Returns the MCP content list."""
    arguments = arguments or {}
    if name == "read_incident_file":
        item = _read_json_file(arguments["path"])
        text = soc_agent.summarize_incident(item)
        return [{"type": "text", "text": text + "\n" + json.dumps(item)}]
    if name == "read_finding_file":
        item = _read_json_file(arguments["path"])
        text = soc_agent.summarize_finding(item)
        return [{"type": "text", "text": text + "\n" + json.dumps(item)}]
    if name == "lookup_guidance":
        entry = soc_agent.lookup_guidance(arguments.get("key"))
        if entry is None:
            return [{"type": "text",
                     "text": "No guidance entry for: "
                             + str(arguments.get("key"))}]
        return [{"type": "text", "text": json.dumps(entry)}]
    if name == "triage_item":
        item = arguments.get("item")
        if not isinstance(item, dict):
            raise ValueError("triage_item needs an 'item' object")
        verdict = soc_agent.triage(item, soc_agent.MockClient())
        return [{"type": "text", "text": json.dumps(verdict)}]
    raise ValueError("unknown tool: " + str(name))


def handle(request):
    """Handle one JSON-RPC request dict; return a response dict or None."""
    if not isinstance(request, dict):
        return {"jsonrpc": "2.0", "id": None,
                "error": {"code": -32600, "message": "Invalid Request"}}
    method = request.get("method")
    request_id = request.get("id")
    # Notifications have no id and get no reply.
    if request_id is None:
        return None
    try:
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": request_id,
                    "result": {"protocolVersion": PROTOCOL_VERSION,
                               "capabilities": {"tools": {}},
                               "serverInfo": SERVER_INFO}}
        if method == "ping":
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": request_id,
                    "result": {"tools": TOOLS}}
        if method == "tools/call":
            params = request.get("params") or {}
            content = call_tool(params.get("name"),
                                params.get("arguments") or {})
            return {"jsonrpc": "2.0", "id": request_id,
                    "result": {"content": content, "isError": False}}
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": -32601,
                          "message": "Method not found: " + str(method)}}
    except Exception as exc:  # tool errors, bad files, bad arguments
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": -32603, "message": str(exc)}}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(json.dumps(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32700, "message": "Parse error"}})
                + "\n")
            sys.stdout.flush()
            continue
        response = handle(request)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
