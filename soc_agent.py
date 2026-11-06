"""SOC Agent step 1: read-only security triage agent.

The agent reads one security item at a time -- a detection incident
(CyberBeep-style) or a scan finding (nmap-triage-style) -- gathers
read-only guidance for it, asks a model for a verdict, and returns a
structured triage report.

Safety rule, by design: the agent only READS and SUGGESTS. It never
runs shell commands, never touches a live system, never blocks an IP,
and never changes anything. Every recommended action needs a human.

Standard library only. No network except an optional local Ollama
model on http://localhost:11434.
"""

import argparse
import json
import os
import re
import sys
import urllib.request

# ---------------------------------------------------------------------------
# Read-only knowledge base: what each item kind usually means, and what a
# human analyst should check next. This is guidance, not a verdict -- the
# model still has to weigh the actual item.
# ---------------------------------------------------------------------------

GUIDANCE = {
    "brute_force": {
        "mitre": "T1110 - Brute Force",
        "meaning": "Many failed logins from one source in a short window.",
        "check_next": "Did any login from that source succeed afterwards?",
        "actions": [
            "Block the source IP at the firewall after human approval",
            "Check whether the targeted account has weak or reused credentials",
        ],
    },
    "login_after_brute_force": {
        "mitre": "T1078 - Valid Accounts",
        "meaning": "A successful login followed a brute-force burst from the "
                   "same source: the password may have been guessed.",
        "check_next": "What did that account access after the login?",
        "actions": [
            "Isolate the affected host and force a password reset",
            "Review the account's activity after the login time",
            "Block the source IP at the firewall after human approval",
        ],
    },
    "wazuh_alert": {
        "mitre": "Varies by rule",
        "meaning": "A host-based alert at or above the configured level.",
        "check_next": "Read the full alert text and the rule that fired.",
        "actions": [
            "Correlate with other alerts from the same host",
        ],
    },
    "ssh": {
        "mitre": "T1021.004 - Remote Services: SSH",
        "meaning": "SSH is exposed. Normal for servers, risky when it faces "
                   "the internet with password login allowed.",
        "check_next": "Is password authentication on, and is this port internet-facing?",
        "actions": [
            "Prefer key-only authentication and disable password login",
            "Restrict SSH to known management addresses where possible",
        ],
    },
    "telnet": {
        "mitre": "T1040 - Network Sniffing",
        "meaning": "Telnet sends credentials in cleartext; anyone on the path "
                   "can read them.",
        "check_next": "Is Telnet actually needed, or left over from setup?",
        "actions": [
            "Disable Telnet and use SSH instead",
        ],
    },
    "http": {
        "mitre": "T1190 - Exploit Public-Facing Application",
        "meaning": "A web service is exposed; its patch level and login pages matter.",
        "check_next": "What software and version serves this port?",
        "actions": [
            "Confirm the service is patched and its admin pages are not public",
        ],
    },
    "rdp": {
        "mitre": "T1021.001 - Remote Services: RDP",
        "meaning": "Remote Desktop exposed to a network is a common entry point "
                   "for ransomware.",
        "check_next": "Is RDP internet-facing, and is Network Level Authentication on?",
        "actions": [
            "Do not expose RDP to the internet; require a VPN gateway",
        ],
    },
}

# The agent's only tools. Every one of them reads; none of them acts.
TOOLS = ["summarize_item", "lookup_guidance"]


def summarize_incident(incident):
    """One readable paragraph describing a detection incident."""
    return (
        "Incident type: {type}. Severity: {severity}. Source: {source}. "
        "Service: {service}. Count: {count}. Detail: {detail}."
    ).format(
        type=incident.get("type", "unknown"),
        severity=incident.get("severity", "unknown"),
        source=incident.get("source_ip", incident.get("ip", "unknown")),
        service=incident.get("service", "unknown"),
        count=incident.get("count", incident.get("failures", "unknown")),
        detail=incident.get("detail", "none given"),
    )


def summarize_finding(finding):
    """One readable paragraph describing a scan finding."""
    return (
        "Open port: {port}/{protocol} on {host}. Service: {service}. "
        "State: {state}."
    ).format(
        port=finding.get("port", "unknown"),
        protocol=finding.get("protocol", "tcp"),
        host=finding.get("host", "unknown"),
        service=finding.get("service", "unknown"),
        state=finding.get("state", "open"),
    )


def lookup_guidance(key):
    """Return the guidance entry for an incident type or service, or None."""
    if key is None:
        return None
    return GUIDANCE.get(str(key).lower())


def build_prompt(summary, guidance):
    """Build the triage prompt: item, guidance, and the verdict format."""
    guide_text = "No specific guidance entry."
    if guidance:
        guide_text = (
            "MITRE: {mitre}\nMeaning: {meaning}\nCheck next: {check}\n"
            "Suggested actions:\n{actions}"
        ).format(
            mitre=guidance["mitre"],
            meaning=guidance["meaning"],
            check=guidance["check_next"],
            actions="\n".join("- " + a for a in guidance["actions"]),
        )
    return (
        "You are a SOC analyst triaging one security item. "
        "Use the item and the guidance, then give a verdict in exactly "
        "this format:\n"
        "VERDICT: <CONFIRMED_THREAT|LIKELY_THREAT|BENIGN|NEEDS_REVIEW>\n"
        "SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW>\n"
        "CAUSE: <one sentence>\n"
        "ACTIONS:\n"
        "- <one action per line>\n"
        "CONFIDENCE: <high|medium|low>\n\n"
        "Item: {summary}\n\nGuidance:\n{guide}\n"
    ).format(summary=summary, guide=guide_text)


def parse_verdict(text):
    """Parse a verdict block. Unparseable output becomes NEEDS_REVIEW."""
    verdict = {
        "verdict": "NEEDS_REVIEW",
        "severity": "UNKNOWN",
        "cause": "Could not parse the model output.",
        "actions": [],
        "confidence": "low",
        "raw": text,
    }
    if not text:
        return verdict
    in_actions = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("VERDICT:"):
            verdict["verdict"] = stripped.split(":", 1)[1].strip()
            in_actions = False
        elif stripped.startswith("SEVERITY:"):
            verdict["severity"] = stripped.split(":", 1)[1].strip()
            in_actions = False
        elif stripped.startswith("CAUSE:"):
            verdict["cause"] = stripped.split(":", 1)[1].strip()
            in_actions = False
        elif stripped.startswith("CONFIDENCE:"):
            verdict["confidence"] = stripped.split(":", 1)[1].strip()
            in_actions = False
        elif stripped.startswith("ACTIONS:"):
            in_actions = True
        elif in_actions and stripped.startswith("- "):
            verdict["actions"].append(stripped[2:].strip())
        elif in_actions and stripped == "":
            in_actions = False
    if verdict["verdict"] != "NEEDS_REVIEW" or verdict["actions"]:
        verdict["cause"] = verdict["cause"] or "No cause given."
    return verdict


class MockClient:
    """Offline stand-in model: verdicts from the item kind, no network."""

    def complete(self, prompt):
        ip_match = re.search(r"\d+\.\d+\.\d+\.\d+", prompt)
        ip = ip_match.group(0) if ip_match else "the source"
        if "login_after_brute_force" in prompt:
            return (
                "VERDICT: CONFIRMED_THREAT\n"
                "SEVERITY: CRITICAL\n"
                "CAUSE: A successful login followed a brute-force burst from "
                "the same source, which strongly indicates the password was guessed.\n"
                "ACTIONS:\n"
                "- Isolate the affected host and force a password reset\n"
                "- Review what the account accessed after the login\n"
                "- Block {ip} at the firewall after human approval\n"
                "CONFIDENCE: high\n"
            ).format(ip=ip)
        if "brute_force" in prompt:
            return (
                "VERDICT: LIKELY_THREAT\n"
                "SEVERITY: HIGH\n"
                "CAUSE: Repeated failed logins from one source look like a "
                "password-guessing attempt, but no success is recorded yet.\n"
                "ACTIONS:\n"
                "- Watch for a successful login from {ip}\n"
                "- Block {ip} at the firewall after human approval\n"
                "CONFIDENCE: medium\n"
            ).format(ip=ip)
        if "telnet" in prompt.lower():
            return (
                "VERDICT: NEEDS_REVIEW\n"
                "SEVERITY: MEDIUM\n"
                "CAUSE: Telnet sends credentials in cleartext, so this "
                "exposure should be removed even though no attack is recorded.\n"
                "ACTIONS:\n"
                "- Disable Telnet and use SSH instead\n"
                "CONFIDENCE: high\n"
            )
        if "ssh" in prompt.lower():
            return (
                "VERDICT: NEEDS_REVIEW\n"
                "SEVERITY: LOW\n"
                "CAUSE: An open SSH port is normal for a server; risk depends "
                "on password login and internet exposure.\n"
                "ACTIONS:\n"
                "- Prefer key-only authentication and disable password login\n"
                "CONFIDENCE: medium\n"
            )
        return (
            "VERDICT: NEEDS_REVIEW\n"
            "SEVERITY: LOW\n"
            "CAUSE: Not enough context to confirm a threat.\n"
            "ACTIONS:\n"
            "- Gather more context about this item\n"
            "CONFIDENCE: low\n"
        )


class OllamaClient:
    """Local Ollama model via its OpenAI-compatible chat endpoint."""

    def __init__(self, model=None, base_url=None):
        self.model = model or os.environ.get("SOC_AGENT_MODEL", "qwen2.5:7b")
        self.base_url = base_url or os.environ.get(
            "SOC_AGENT_OLLAMA_URL", "http://localhost:11434"
        )

    def complete(self, prompt):
        payload = json.dumps(
            {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + "/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                body = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise RuntimeError(
                "Ollama request failed (is 'ollama serve' running?): {exc}".format(
                    exc=exc
                )
            )
        return body["message"]["content"]


def triage(item, client):
    """Triage one item and return the structured verdict dict."""
    if "port" in item:
        summary = summarize_finding(item)
        guidance = lookup_guidance(item.get("service"))
    else:
        summary = summarize_incident(item)
        guidance = lookup_guidance(item.get("type"))
    prompt = build_prompt(summary, guidance)
    verdict = parse_verdict(client.complete(prompt))
    verdict["item"] = summary
    verdict["guidance_mitre"] = guidance["mitre"] if guidance else None
    return verdict


def format_report(verdict):
    """Render a verdict dict as a short analyst-style report."""
    lines = [
        "Verdict:  " + verdict["verdict"],
        "Severity: " + verdict["severity"],
        "Cause:    " + verdict["cause"],
        "Confidence: " + verdict["confidence"],
        "Item:     " + verdict["item"],
    ]
    if verdict.get("guidance_mitre"):
        lines.append("MITRE:    " + verdict["guidance_mitre"])
    lines.append("Recommended actions (human approval required):")
    for action in verdict["actions"]:
        lines.append("  - " + action)
    return "\n".join(lines)


SAMPLE_INCIDENT = {
    "type": "login_after_brute_force",
    "severity": "CRITICAL",
    "source_ip": "203.0.113.45",
    "service": "ssh",
    "count": 14,
    "detail": "14 failed SSH logins in 5 minutes, then a successful login",
}

SAMPLE_FINDING = {
    "port": 23,
    "protocol": "tcp",
    "service": "telnet",
    "state": "open",
    "host": "192.168.1.10",
}


def main(argv=None):
    parser = argparse.ArgumentParser(description="SOC Agent step 1: triage.")
    parser.add_argument("--demo", action="store_true",
                        help="triage the built-in sample incident and finding")
    parser.add_argument("--incident-file",
                        help="path to a JSON incident file")
    parser.add_argument("--finding-file",
                        help="path to a JSON scan-finding file")
    parser.add_argument("--model", default="mock", choices=["mock", "ollama"],
                        help="model backend (default: mock, offline)")
    args = parser.parse_args(argv)

    client = OllamaClient() if args.model == "ollama" else MockClient()

    items = []
    if args.demo:
        items = [SAMPLE_INCIDENT, SAMPLE_FINDING]
    if args.incident_file:
        with open(args.incident_file, "r", encoding="utf-8") as handle:
            items.append(json.load(handle))
    if args.finding_file:
        with open(args.finding_file, "r", encoding="utf-8") as handle:
            items.append(json.load(handle))
    if not items:
        parser.error("nothing to triage: pass --demo, --incident-file, "
                     "or --finding-file")

    for item in items:
        print(format_report(triage(item, client)))
        print("-" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
