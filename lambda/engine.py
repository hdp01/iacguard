"""Runs the rule set over a parsed Terraform document."""

from parser import Document
from rules import RULES

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_WEIGHT = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1}


def extract_snippet(source: str, line: int, max_lines: int = 40) -> str:
    """Return the Terraform block starting at `line` by balancing braces.

    The snippet is what Nova sees, so it needs to be the whole block rather
    than a fixed window: a rule about a nested ingress block is meaningless
    without the braces around it.
    """
    if line < 1:
        return ""
    lines = source.splitlines()
    if line > len(lines):
        return ""
    collected, depth, started = [], 0, False
    for raw in lines[line - 1: line - 1 + max_lines]:
        collected.append(raw)
        depth += raw.count("{") - raw.count("}")
        if "{" in raw:
            started = True
        if started and depth <= 0:
            break
    return "\n".join(collected)


def score(findings: list[dict]) -> int:
    """A 0-100 posture score: 100 is clean, and each finding subtracts by
    severity. Capped at zero so a very bad file reads as 0 rather than
    negative."""
    penalty = sum(SEVERITY_WEIGHT.get(f["severity"], 1) for f in findings)
    return max(0, 100 - penalty)


def scan_source(source: str, filename: str) -> list[dict]:
    doc = Document(source, filename)
    blocks = doc.resources + doc.variables
    findings = []

    for block in blocks:
        kind = "variable" if block["type"] == "variable" else block["type"]
        for rule in RULES:
            # applies_to is a resource type, a tuple of them, or "*" for any.
            targets = (rule.applies_to if isinstance(rule.applies_to, tuple)
                       else (rule.applies_to,))
            if "*" not in targets and kind not in targets:
                continue
            # "*" rules are about resource attributes; variables are covered
            # by their own dedicated rules instead.
            if "*" in targets and kind == "variable":
                continue
            try:
                detail = rule.check(block, doc)
            except Exception as exc:  # a bad rule must not fail the whole scan
                print(f"rule {rule.id} errored on {block['name']}: {exc}")
                continue
            if not detail:
                continue
            findings.append(
                {
                    "rule_id": rule.id,
                    "severity": rule.severity,
                    "title": rule.title,
                    "rationale": rule.rationale,
                    "resource_type": block["type"],
                    "resource_name": block["name"],
                    "file": filename,
                    "line": block["line"],
                    "detail": detail,
                    "snippet": extract_snippet(source, block["line"]),
                }
            )

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9),
                                 f["rule_id"]))
    return findings


def summarise(findings: list[dict]) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {
        "total": len(findings),
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "score": score(findings),
    }
