"""Amazon Nova remediation: explain each finding and rewrite the code.

One Bedrock call per finding, fanned out across a small thread pool. Findings
are independent, so the wall-clock cost of a scan is roughly the slowest
single call rather than the sum of them.
"""

import json
import os
import re
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.config import Config

MODEL_ID = os.environ.get("NOVA_MODEL_ID", "amazon.nova-lite-v1:0")
MAX_WORKERS = int(os.environ.get("REMEDIATION_CONCURRENCY", "4"))
MAX_FINDINGS = int(os.environ.get("MAX_REMEDIATIONS", "25"))

# Bedrock calls are the slow part of the function; a bounded retry keeps a
# throttle from failing the whole scan.
#
# The budget is deliberately generous. Bedrock throttles per account, not per
# function, so a burst of concurrent scans contends with itself: a 20-scan load
# test exhausted 4 attempts and lost the AI text on roughly 10% of findings.
# Adaptive mode adds client-side rate limiting on top of the backoff.
_bedrock = boto3.client(
    "bedrock-runtime",
    config=Config(retries={"max_attempts": 8, "mode": "adaptive"},
                  read_timeout=60),
)

SYSTEM = [
    {
        "text": (
            "You are a cloud security engineer reviewing Terraform. "
            "For each finding you receive, explain the real-world risk in "
            "plain language a junior engineer would understand, then rewrite "
            "the Terraform block so the issue is fixed.\n\n"
            "Rules:\n"
            "- Reply with ONE JSON object and nothing else.\n"
            "- Keys: \"explanation\" (2-3 sentences, plain language, no "
            "jargon without explaining it), \"fixed_code\" (valid Terraform "
            "for the corrected block only), \"effort\" (one of \"trivial\", "
            "\"moderate\", \"involved\").\n"
            "- Keep the resource name and type unchanged so the fix is a "
            "drop-in replacement.\n"
            "- Do not invent attributes that do not exist in the AWS "
            "provider."
        )
    }
]

_JSON_RE = re.compile(r"\{.*\}", re.S)


def _parse(text: str) -> dict:
    """Nova usually returns clean JSON, but may wrap it in a fenced block."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = _JSON_RE.search(text)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    # Last resort: keep the prose so the report is still useful.
    return {"explanation": text.strip()[:800], "fixed_code": "",
            "effort": "unknown"}


def _prompt(finding: dict) -> str:
    return (
        f"Rule: {finding['rule_id']} - {finding['title']}\n"
        f"Severity: {finding['severity']}\n"
        f"Why it matters: {finding['rationale']}\n"
        f"What was detected: {finding['detail']}\n"
        f"Resource: {finding['resource_type']}.{finding['resource_name']} "
        f"({finding['file']} line {finding['line']})\n\n"
        f"Terraform block:\n```hcl\n{finding['snippet']}\n```"
    )


def _one(finding: dict) -> dict:
    try:
        response = _bedrock.converse(
            modelId=MODEL_ID,
            system=SYSTEM,
            messages=[{"role": "user",
                       "content": [{"text": _prompt(finding)}]}],
            inferenceConfig={"maxTokens": 1200, "temperature": 0.2,
                             "topP": 0.9},
        )
        text = response["output"]["message"]["content"][0]["text"]
        usage = response.get("usage", {})
        parsed = _parse(text)
        return {
            **finding,
            "explanation": parsed.get("explanation", ""),
            "fixed_code": parsed.get("fixed_code", ""),
            "effort": parsed.get("effort", "unknown"),
            "tokens_in": usage.get("inputTokens", 0),
            "tokens_out": usage.get("outputTokens", 0),
            "ai_status": "ok",
        }
    except Exception as exc:
        # A Bedrock failure degrades the report; it must not lose the finding,
        # which was produced deterministically and is valid on its own.
        print(f"bedrock failed for {finding['rule_id']}: {exc}")
        return {**finding, "explanation": "", "fixed_code": "",
                "effort": "unknown", "tokens_in": 0, "tokens_out": 0,
                "ai_status": f"error: {type(exc).__name__}"}


def remediate(findings: list[dict]) -> tuple[list[dict], dict]:
    """Enrich findings with Nova output. Returns (findings, token usage)."""
    target = findings[:MAX_FINDINGS]
    overflow = findings[MAX_FINDINGS:]

    if target:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            enriched = list(pool.map(_one, target))
    else:
        enriched = []

    for finding in overflow:
        finding.update({"explanation": "", "fixed_code": "",
                        "effort": "unknown", "tokens_in": 0, "tokens_out": 0,
                        "ai_status": "skipped: per-scan remediation limit"})

    all_findings = enriched + overflow
    usage = {
        "tokens_in": sum(f.get("tokens_in", 0) for f in all_findings),
        "tokens_out": sum(f.get("tokens_out", 0) for f in all_findings),
        "remediated": sum(1 for f in all_findings
                          if f.get("ai_status") == "ok"),
    }
    return all_findings, usage
