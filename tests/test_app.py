"""Tests for SOC Agent step 4 (phone web app). Standard library only.

Spins up the real server on an ephemeral port and drives it over HTTP.
"""

import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app"))

import server as app_server
import soc_agent


class AppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = app_server.create_server(0, "127.0.0.1")
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def url(self, path):
        return "http://127.0.0.1:{port}{path}".format(port=self.port,
                                                  path=path)

    def get(self, path):
        with urllib.request.urlopen(self.url(path), timeout=10) as resp:
            return resp.status, resp.read()

    def post(self, path, payload, raw=None):
        data = raw if raw is not None else json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.url(path), data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_home_page_serves(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"SOC Agent", body)
        self.assertIn(b"manifest.json", body)

    def test_home_page_has_face(self):
        # Step 5: the particle humanoid that shows the agent's state.
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b'id="face"', body)
        self.assertIn(b"Speak verdicts", body)
        self.assertIn(b"face-status", body)

    def test_health(self):
        status, body = self.get("/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])

    def test_evals_endpoint_reports_full_marks(self):
        status, body = self.get("/api/evals")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["passed"], 12)
        self.assertEqual(data["total"], 12)
        self.assertEqual(data["percent"], 100)

    def test_triage_sample_incident(self):
        status, data = self.post("/api/triage",
                                 {"item": soc_agent.SAMPLE_INCIDENT})
        self.assertEqual(status, 200)
        self.assertEqual(data["verdict"], "CONFIRMED_THREAT")
        self.assertEqual(data["severity"], "CRITICAL")
        self.assertEqual(data["guidance_mitre"], "T1078 - Valid Accounts")

    def test_triage_sample_finding(self):
        status, data = self.post("/api/triage",
                                 {"item": soc_agent.SAMPLE_FINDING})
        self.assertEqual(status, 200)
        self.assertEqual(data["verdict"], "NEEDS_REVIEW")
        self.assertEqual(data["severity"], "MEDIUM")

    def test_triage_rejects_bad_json(self):
        status, data = self.post("/api/triage", None, raw=b"{not json")
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_triage_rejects_missing_item(self):
        status, data = self.post("/api/triage", {"model": "mock"})
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_triage_rejects_bad_model(self):
        status, data = self.post("/api/triage",
                                 {"item": soc_agent.SAMPLE_INCIDENT,
                                  "model": "gpt-99"})
        self.assertEqual(status, 400)
        self.assertIn("error", data)

    def test_manifest_serves(self):
        status, body = self.get("/manifest.json")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["name"], "SOC Agent")

    def test_icons_are_png(self):
        for path in ("/icon-192.png", "/icon-512.png"):
            status, body = self.get(path)
            self.assertEqual(status, 200)
            self.assertTrue(body.startswith(b"\x89PNG\r\n\x1a\n"), path)

    def test_unknown_path_404s(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.get("/no-such-page")
        self.assertEqual(caught.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
