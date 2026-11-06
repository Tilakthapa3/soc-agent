"""Tests for SOC Agent step 3 (evals). Standard library unittest only."""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evals
import soc_agent


class LoadCasesTests(unittest.TestCase):
    def test_cases_file_loads(self):
        cases = evals.load_cases(evals.DEFAULT_CASES)
        self.assertEqual(len(cases), 12)

    def test_every_case_has_required_fields(self):
        cases = evals.load_cases(evals.DEFAULT_CASES)
        for case in cases:
            for field in ("id", "item", "expected_verdict",
                          "expected_severity"):
                self.assertIn(field, case, case.get("id"))

    def test_case_ids_are_unique(self):
        cases = evals.load_cases(evals.DEFAULT_CASES)
        ids = [case["id"] for case in cases]
        self.assertEqual(len(ids), len(set(ids)))

    def test_case_file_is_valid_json(self):
        with open(evals.DEFAULT_CASES, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertIn("cases", data)

    def test_missing_field_raises(self):
        bad = [{"id": "broken", "item": {"type": "brute_force"}}]
        path = os.path.join(os.path.dirname(__file__), "_bad_cases.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"cases": bad}, handle)
        try:
            with self.assertRaises(ValueError):
                evals.load_cases(path)
        finally:
            os.remove(path)


class RunEvalsTests(unittest.TestCase):
    def setUp(self):
        self.cases = evals.load_cases(evals.DEFAULT_CASES)
        self.client = soc_agent.MockClient()

    def test_mock_scores_full_marks(self):
        _, passed, total = evals.run_evals(self.cases, self.client)
        self.assertEqual(passed, total)
        self.assertEqual(total, 12)

    def test_wrong_expectation_fails_that_case(self):
        cases = copy.deepcopy(self.cases)
        cases[0]["expected_verdict"] = "BENIGN"
        results, passed, total = evals.run_evals(cases, self.client)
        self.assertFalse(results[0]["passed"])
        self.assertEqual(passed, total - 1)

    def test_result_carries_got_and_expected(self):
        result = evals.run_case(self.cases[0], self.client)
        self.assertEqual(result["id"], "login-after-brute-force-1")
        self.assertEqual(result["verdict"], "CONFIRMED_THREAT")
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertTrue(result["passed"])

    def test_score_line_renders(self):
        results, passed, total = evals.run_evals(self.cases, self.client)
        text = evals.format_results(results, passed, total)
        self.assertIn("Score: 12/12 (100%)", text)
        self.assertIn("[PASS]", text)
        self.assertNotIn("[FAIL]", text)

    def test_evals_module_is_stdlib_only(self):
        with open(evals.__file__) as handle:
            source = handle.read()
        self.assertNotIn("subprocess", source)


if __name__ == "__main__":
    unittest.main()
