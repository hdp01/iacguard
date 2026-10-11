"""IaCGuard scanner Lambda.

Triggered by S3 ObjectCreated. The CLI uploads to
``uploads/<scan_id>/<filename>.tf``, so the scan id travels in the object key
and the CLI can poll for its own results without a lookup API.

A directory scan uploads several files under one scan id, producing one
invocation per file. Counters on the META item are therefore incremented with
atomic ADD rather than written wholesale, so concurrent invocations aggregate
instead of overwriting each other.
"""

import os
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

import boto3

import engine
import remediate

TABLE_NAME = os.environ["TABLE_NAME"]
NAMESPACE = os.environ.get("METRIC_NAMESPACE", "IaCGuard")
RESULT_TTL_DAYS = int(os.environ.get("RESULT_TTL_DAYS", "30"))
MAX_BYTES = int(os.environ.get("MAX_FILE_BYTES", str(1024 * 1024)))

s3 = boto3.client("s3")
table = boto3.resource("dynamodb").Table(TABLE_NAME)
cloudwatch = boto3.client("cloudwatch")


def _ttl() -> int:
    return int((datetime.now(timezone.utc)
                + timedelta(days=RESULT_TTL_DAYS)).timestamp())


def _publish_metrics(summary: dict, usage: dict, duration_ms: float) -> None:
    """Custom metrics are what make the CloudWatch dashboard meaningful;
    Lambda's built-ins only describe the function, not the scans."""
    metrics = [
        ("ScansCompleted", 1, "Count"),
        ("FindingsTotal", summary["total"], "Count"),
        ("CriticalFindings", summary["critical"], "Count"),
        ("HighFindings", summary["high"], "Count"),
        ("PostureScore", summary["score"], "None"),
        ("NovaInputTokens", usage["tokens_in"], "Count"),
        ("NovaOutputTokens", usage["tokens_out"], "Count"),
        ("ScanDuration", duration_ms, "Milliseconds"),
    ]
    try:
        cloudwatch.put_metric_data(
            Namespace=NAMESPACE,
            MetricData=[
                {"MetricName": name, "Value": value, "Unit": unit}
                for name, value, unit in metrics
            ],
        )
    except Exception as exc:
        # Losing a metric must never fail a scan whose results are already
        # safely in DynamoDB.
        print(f"put_metric_data failed: {exc}")


def _persist(scan_id: str, filename: str, findings: list[dict],
             summary: dict, usage: dict) -> None:
    expires = _ttl()

    with table.batch_writer() as batch:
        for index, finding in enumerate(findings):
            batch.put_item(
                Item={
                    "scan_id": scan_id,
                    "sk": f"FINDING#{filename}#{index:03d}",
                    "expires_at": expires,
                    **{k: v for k, v in finding.items() if v != ""},
                }
            )

    table.update_item(
        Key={"scan_id": scan_id, "sk": "META"},
        UpdateExpression=(
            "SET #st = :running, expires_at = :ttl, "
            "created_at = if_not_exists(created_at, :now), "
            "updated_at = :now "
            "ADD files_scanned :one, total_findings :total, "
            "critical_count :crit, high_count :high, "
            "medium_count :med, low_count :low, "
            "penalty :penalty, tokens_in :tin, tokens_out :tout"
        ),
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":running": "complete",
            ":ttl": expires,
            ":now": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            ":one": 1,
            ":total": summary["total"],
            ":crit": summary["critical"],
            ":high": summary["high"],
            ":med": summary["medium"],
            ":low": summary["low"],
            ":penalty": 100 - summary["score"],
            ":tin": usage["tokens_in"],
            ":tout": usage["tokens_out"],
        },
    )


def _scan_id_from_key(key: str) -> tuple[str, str]:
    """uploads/<scan_id>/<filename> -> (scan_id, filename)"""
    parts = key.split("/")
    if len(parts) >= 3 and parts[0] == "uploads":
        return parts[1], parts[-1]
    return "unprefixed", parts[-1]


def handler(event, context):
    results = []

    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
        size = record["s3"]["object"].get("size", 0)
        started = time.time()

        scan_id, filename = _scan_id_from_key(key)
        print(f"scanning s3://{bucket}/{key} as scan {scan_id}")

        if size > MAX_BYTES:
            print(f"skipping {key}: {size} bytes exceeds {MAX_BYTES}")
            results.append({"key": key, "status": "too_large"})
            continue

        if not filename.endswith((".tf", ".tf.json", ".hcl")):
            print(f"skipping {key}: not a Terraform file")
            results.append({"key": key, "status": "unsupported"})
            continue

        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        source = body.decode("utf-8", errors="replace")

        try:
            findings = engine.scan_source(source, filename)
        except Exception as exc:
            print(f"parse failed for {key}: {exc}")
            table.update_item(
                Key={"scan_id": scan_id, "sk": "META"},
                UpdateExpression=(
                    "SET #st = :failed, parse_error = :err, "
                    "expires_at = :ttl"
                ),
                ExpressionAttributeNames={"#st": "status"},
                ExpressionAttributeValues={
                    ":failed": "parse_error",
                    ":err": f"{filename}: {exc}"[:500],
                    ":ttl": _ttl(),
                },
            )
            results.append({"key": key, "status": "parse_error"})
            continue

        summary = engine.summarise(findings)
        findings, usage = remediate.remediate(findings)
        _persist(scan_id, filename, findings, summary, usage)

        duration_ms = (time.time() - started) * 1000
        _publish_metrics(summary, usage, duration_ms)

        print(f"scan {scan_id} {filename}: {summary['total']} findings, "
              f"score {summary['score']}, {usage['remediated']} remediated, "
              f"{duration_ms:.0f}ms")
        results.append({"key": key, "scan_id": scan_id,
                        "status": "complete", **summary})

    return {"results": results}
