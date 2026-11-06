"""SOC Agent step 3: evals.

Runs the agent over a set of labeled cases (evals/cases.json) and
reports a score: how many cases got the expected verdict AND severity.

With the mock model the score is a regression check -- it proves the
triage pipeline still behaves as designed. With a real model
(--model ollama) the same cases measure real accuracy, so the score
can be compared across models and over time.

Standard library only. Usage:

    python3 evals.py                 # mock model (offline)
    python3 evals.py --model ollama  # local Ollama model
    python3 evals.py --cases path/to/cases.json

Exit code is 0 when every case passes, 1 otherwise.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import soc_agent

DEFAULT_CASES = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "evals", "cases.json"
)


def load_cases(path):
    """Load the labeled eval cases from a JSON file."""
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    cases = data["cases"] if isinstance(data, dict) else data
    for case in cases:
        for field in ("id", "item", "expected_verdict", "expected_severity"):
            if field not in case:
                raise ValueError(
                    "eval case is missing {field!r}: {case!r}".format(
                        field=field, case=case
                    )
                )
    return cases


def run_case(case, client):
    """Triage one case and compare the verdict against its labels."""
    verdict = soc_agent.triage(case["item"], client)
    passed = (
        verdict["verdict"] == case["expected_verdict"]
        and verdict["severity"] == case["expected_severity"]
    )
    return {
        "id": case["id"],
        "name": case.get("name", case["id"]),
        "expected_verdict": case["expected_verdict"],
        "expected_severity": case["expected_severity"],
        "verdict": verdict["verdict"],
        "severity": verdict["severity"],
        "confidence": verdict["confidence"],
        "passed": passed,
    }


def run_evals(cases, client):
    """Run every case and return (results, passed_count, total)."""
    results = [run_case(case, client) for case in cases]
    passed = sum(1 for result in results if result["passed"])
    return results, passed, len(results)


def format_results(results, passed, total):
    """Render the per-case table and the score line."""
    lines = []
    for result in results:
        mark = "PASS" if result["passed"] else "FAIL"
        lines.append(
            "[{mark}] {name}: got {verdict}/{severity}, "
            "expected {expected_verdict}/{expected_severity} "
            "(confidence: {confidence})".format(
                mark=mark,
                name=result["name"],
                verdict=result["verdict"],
                severity=result["severity"],
                expected_verdict=result["expected_verdict"],
                expected_severity=result["expected_severity"],
                confidence=result["confidence"],
            )
        )
    percent = (100 * passed // total) if total else 0
    lines.append("Score: {passed}/{total} ({percent}%)".format(
        passed=passed, total=total, percent=percent
    ))
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="SOC Agent step 3: evals.")
    parser.add_argument("--cases", default=DEFAULT_CASES,
                        help="path to the labeled cases JSON file")
    parser.add_argument("--model", default="mock", choices=["mock", "ollama"],
                        help="model backend (default: mock, offline)")
    args = parser.parse_args(argv)

    client = soc_agent.OllamaClient() if args.model == "ollama" \
        else soc_agent.MockClient()
    cases = load_cases(args.cases)
    results, passed, total = run_evals(cases, client)
    print(format_results(results, passed, total))
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
