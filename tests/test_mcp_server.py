"""Tests for SOC Agent step 2 (MCP server). Stdlib unittest only.

Spawns the real server as a subprocess over stdio and speaks
newline-delimited JSON-RPC to it, the way an MCP client would.
"""

import json
import os
import subprocess
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(BASE, "mcp_server.py")


class McpClient:
    """Minimal JSON-RPC client for the test server process."""

    def __init__(self):
        self.proc = subprocess.Popen(
            [sys.executable, SERVER],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            text=True, cwd=BASE)
        self.next_id = 1

    def request(self, method, params=None):
        rid = self.next_id
        self.next_id += 1
        payload = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            payload["params"] = params
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        assert line, "server closed stdout without a reply"
        reply = json.loads(line)
        assert reply.get("id") == rid, reply
        return reply

    def notify(self, method):
        self.proc.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
        self.proc.stdin.flush()

    def close(self):
        try:
            self.proc.stdin.close()
        except BrokenPipeError:
            pass
        self.proc.wait(timeout=10)
        self.proc.stdout.close()


class McpServerTests(unittest.TestCase):
    def setUp(self):
        self.client = McpClient()

    def tearDown(self):
        self.client.close()

    def test_initialize(self):
        reply = self.client.request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0.1"}})
        self.assertIn("result", reply)
        self.assertEqual(reply["result"]["serverInfo"]["name"],
                         "soc-agent")
        self.assertIn("tools", reply["result"]["capabilities"])
        # Notifications get no reply: the next request must still work.
        self.client.notify("notifications/initialized")
        self.assertIn("result", self.client.request("ping"))

    def test_tools_list_is_four_read_only_tools(self):
        reply = self.client.request("tools/list")
        names = [t["name"] for t in reply["result"]["tools"]]
        self.assertEqual(names, ["read_incident_file", "read_finding_file",
                                 "lookup_guidance", "triage_item"])
        with open(SERVER) as handle:
            source = handle.read()
        self.assertNotIn("subprocess", source)
        self.assertNotIn("os.system", source)

    def test_read_incident_file(self):
        path = os.path.join(BASE, "examples", "sample_incident.json")
        reply = self.client.request("tools/call", {
            "name": "read_incident_file", "arguments": {"path": path}})
        text = reply["result"]["content"][0]["text"]
        self.assertIn("203.0.113.45", text)
        self.assertIn("login_after_brute_force", text)

    def test_read_finding_file(self):
        path = os.path.join(BASE, "examples", "sample_finding.json")
        reply = self.client.request("tools/call", {
            "name": "read_finding_file", "arguments": {"path": path}})
        text = reply["result"]["content"][0]["text"]
        self.assertIn("telnet", text)
        self.assertIn("192.168.1.10", text)

    def test_lookup_guidance(self):
        reply = self.client.request("tools/call", {
            "name": "lookup_guidance",
            "arguments": {"key": "login_after_brute_force"}})
        entry = json.loads(reply["result"]["content"][0]["text"])
        self.assertEqual(entry["mitre"], "T1078 - Valid Accounts")

    def test_lookup_guidance_unknown_key(self):
        reply = self.client.request("tools/call", {
            "name": "lookup_guidance",
            "arguments": {"key": "not_a_real_kind"}})
        self.assertIn("No guidance entry",
                      reply["result"]["content"][0]["text"])

    def test_triage_item_via_mcp(self):
        import soc_agent
        reply = self.client.request("tools/call", {
            "name": "triage_item",
            "arguments": {"item": soc_agent.SAMPLE_INCIDENT}})
        verdict = json.loads(reply["result"]["content"][0]["text"])
        self.assertEqual(verdict["verdict"], "CONFIRMED_THREAT")
        self.assertEqual(verdict["severity"], "CRITICAL")

    def test_unknown_tool_is_an_error(self):
        reply = self.client.request("tools/call", {
            "name": "delete_everything", "arguments": {}})
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32603)

    def test_unknown_method_is_an_error(self):
        reply = self.client.request("resources/list")
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32601)


if __name__ == "__main__":
    unittest.main()
