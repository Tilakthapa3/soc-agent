"""Tests for SOC Agent step 1. Standard library unittest only."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import soc_agent


class GuidanceTests(unittest.TestCase):
    def test_known_incident_type(self):
        entry = soc_agent.lookup_guidance("brute_force")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["mitre"], "T1110 - Brute Force")

    def test_service_lookup_is_case_insensitive(self):
        self.assertIsNotNone(soc_agent.lookup_guidance("SSH"))
        self.assertIsNotNone(soc_agent.lookup_guidance("Telnet"))

    def test_unknown_key_returns_none(self):
        self.assertIsNone(soc_agent.lookup_guidance("not_a_real_kind"))
        self.assertIsNone(soc_agent.lookup_guidance(None))

    def test_tools_are_read_only(self):
        # The agent's tool list must never gain an acting tool.
        self.assertEqual(
            soc_agent.TOOLS, ["summarize_item", "lookup_guidance"]
        )
        with open(soc_agent.__file__) as handle:
            source = handle.read()
        self.assertNotIn("subprocess", source)


class SummarizeTests(unittest.TestCase):
    def test_incident_summary_carries_key_fields(self):
        text = soc_agent.summarize_incident(soc_agent.SAMPLE_INCIDENT)
        self.assertIn("203.0.113.45", text)
        self.assertIn("login_after_brute_force", text)
        self.assertIn("CRITICAL", text)

    def test_finding_summary_carries_key_fields(self):
        text = soc_agent.summarize_finding(soc_agent.SAMPLE_FINDING)
        self.assertIn("23", text)
        self.assertIn("telnet", text)
        self.assertIn("192.168.1.10", text)


class ParseTests(unittest.TestCase):
    def test_well_formed_verdict_parses(self):
        text = (
            "VERDICT: LIKELY_THREAT\n"
            "SEVERITY: HIGH\n"
            "CAUSE: Repeated failures look like guessing.\n"
            "ACTIONS:\n"
            "- Watch the source\n"
            "- Block after approval\n"
            "CONFIDENCE: medium\n"
        )
        verdict = soc_agent.parse_verdict(text)
        self.assertEqual(verdict["verdict"], "LIKELY_THREAT")
        self.assertEqual(verdict["severity"], "HIGH")
        self.assertEqual(verdict["actions"],
                         ["Watch the source", "Block after approval"])
        self.assertEqual(verdict["confidence"], "medium")

    def test_garbage_output_becomes_needs_review(self):
        verdict = soc_agent.parse_verdict("hello, this is not a verdict")
        self.assertEqual(verdict["verdict"], "NEEDS_REVIEW")
        self.assertEqual(verdict["confidence"], "low")

    def test_empty_output_becomes_needs_review(self):
        self.assertEqual(soc_agent.parse_verdict("")["verdict"],
                         "NEEDS_REVIEW")


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.client = soc_agent.MockClient()

    def test_login_after_brute_force_is_confirmed(self):
        verdict = soc_agent.triage(soc_agent.SAMPLE_INCIDENT, self.client)
        self.assertEqual(verdict["verdict"], "CONFIRMED_THREAT")
        self.assertEqual(verdict["severity"], "CRITICAL")
        self.assertEqual(verdict["guidance_mitre"],
                         "T1078 - Valid Accounts")
        self.assertTrue(any("203.0.113.45" in a
                            for a in verdict["actions"]))

    def test_plain_brute_force_is_likely_not_confirmed(self):
        incident = dict(soc_agent.SAMPLE_INCIDENT)
        incident["type"] = "brute_force"
        incident["severity"] = "HIGH"
        incident["detail"] = "12 failed SSH logins in 5 minutes"
        verdict = soc_agent.triage(incident, self.client)
        self.assertEqual(verdict["verdict"], "LIKELY_THREAT")
        self.assertEqual(verdict["severity"], "HIGH")

    def test_telnet_finding_needs_review(self):
        verdict = soc_agent.triage(soc_agent.SAMPLE_FINDING, self.client)
        self.assertEqual(verdict["verdict"], "NEEDS_REVIEW")
        self.assertEqual(verdict["severity"], "MEDIUM")
        self.assertTrue(any("SSH" in a for a in verdict["actions"]))

    def test_report_renders(self):
        verdict = soc_agent.triage(soc_agent.SAMPLE_INCIDENT, self.client)
        report = soc_agent.format_report(verdict)
        self.assertIn("CONFIRMED_THREAT", report)
        self.assertIn("human approval required", report)


class ExampleFileTests(unittest.TestCase):
    def test_example_files_parse_and_triage(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        client = soc_agent.MockClient()
        for name in ("sample_incident.json", "sample_finding.json"):
            path = os.path.join(base, "examples", name)
            with open(path, "r", encoding="utf-8") as handle:
                item = json.load(handle)
            verdict = soc_agent.triage(item, client)
            self.assertIn(verdict["verdict"],
                          ("CONFIRMED_THREAT", "LIKELY_THREAT",
                           "BENIGN", "NEEDS_REVIEW"))


if __name__ == "__main__":
    unittest.main()
