# SOC Agent

A read-only security triage agent. It reads one security item at a time —
a detection incident (CyberBeep-style) or a scan finding (nmap-triage-style)
— gathers guidance for it, asks a model for a verdict, and returns a short
analyst-style report: verdict, severity, cause, recommended actions, and
confidence.

## The one safety rule

The agent only reads and suggests. It never runs shell commands, never
touches a live system, never blocks an IP, and never changes anything.
Every recommended action needs a human. This is deliberate: a triage agent
that acts on its own is a liability, not a tool.

## Step 1 (done)

- `soc_agent.py`: triage loop, read-only guidance knowledge base
  (MITRE technique, meaning, what to check next), verdict parsing,
  mock model for offline demo, and an optional local Ollama backend.
- `tests/test_soc_agent.py`: 14 tests covering guidance, summaries,
  verdict parsing, triage outcomes, and the example files.
- `examples/`: a sample CyberBeep-style incident and a sample
  nmap-style finding.

## Usage

```sh
# Offline demo (mock model, no network, no keys)
python3 soc_agent.py --demo

# Triage your own files
python3 soc_agent.py --incident-file examples/sample_incident.json
python3 soc_agent.py --finding-file examples/sample_finding.json

# With a local Ollama model (needs `ollama serve` running)
python3 soc_agent.py --demo --model ollama

# Score the agent on the labeled eval cases
python3 evals.py
python3 evals.py --model ollama
```

## Step 2 (done)

- `mcp_server.py`: MCP server (JSON-RPC 2.0, newline-delimited, over
  stdio) exposing four read-only tools — `read_incident_file`,
  `read_finding_file`, `lookup_guidance`, `triage_item` — so an MCP
  client can give an AI safe tool access to real inputs instead of
  the built-in guidance table.
- `tests/test_mcp_server.py`: 9 tests driving the real server as a
  subprocess (initialize, tools/list, all four tools, unknown
  tool/method errors). Total: 23 tests passing.
- Run it: `python3 mcp_server.py` (then send JSON-RPC lines on stdin).

## Step 3 (done)

- `evals.py` + `evals/cases.json`: 12 labeled cases (brute-force bursts,
  logins after bursts, open Telnet/SSH/HTTP/RDP ports, a Wazuh alert,
  unknown types and services) with known correct verdicts and severities.
  `python3 evals.py` scores the agent: **12/12 (100%)** with the mock
  model. The same cases run against a real model with
  `python3 evals.py --model ollama`, so accuracy is a number that can be
  compared across models and over time.
- `tests/test_evals.py`: 10 tests (case file validity, full-marks run,
  wrong-expectation failure, score line). Total: 33 tests passing.

## Roadmap

- Later: a CyberBeep adapter (read `incidents.jsonl` directly) and an
  nmap-triage adapter (read triage findings directly).

## Requirements

Python 3.8+. Standard library only. Ollama is optional.
