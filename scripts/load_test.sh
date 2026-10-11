#!/usr/bin/env bash
# Fires N concurrent scans to demonstrate scaling.
#
# Each upload becomes its own scan id, so Lambda scales out horizontally with
# no capacity planning and nothing provisioned in advance. On an account whose
# concurrency limit is low this will also produce Throttles, which is the
# expected and correct behaviour of the cap rather than a failure.
#
#   ./scripts/load_test.sh 20
set -euo pipefail

COUNT="${1:-20}"
PARALLEL="${PARALLEL:-10}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUCKET="$(python3 -c "import json; print(json.load(open('$ROOT/.iacguard.json'))['bucket'])")"
REGION="$(python3 -c "import json; print(json.load(open('$ROOT/.iacguard.json'))['region'])")"
STAMP="$(date +%s)"

echo "Firing $COUNT scans at $BUCKET ($PARALLEL at a time)"
start=$(date +%s)

seq 1 "$COUNT" | xargs -P "$PARALLEL" -I{} \
  aws s3 cp "$ROOT/samples/insecure.tf" \
    "s3://$BUCKET/uploads/load-$STAMP-{}/insecure.tf" \
    --region "$REGION" --only-show-errors

echo "All $COUNT uploads issued in $(( $(date +%s) - start ))s"
echo
echo "Watch it drain:"
echo "  aws logs tail /aws/lambda/iacguard-scanner --region $REGION --follow"
echo "  ./scripts/metrics.sh"
