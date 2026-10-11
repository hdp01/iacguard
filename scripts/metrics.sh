#!/usr/bin/env bash
# Prints the custom IaCGuard metrics and the Lambda built-ins for the last
# hour. Useful for confirming the dashboard has data before screenshotting it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="$(python3 -c "import json; print(json.load(open('$ROOT/.iacguard.json'))['region'])")"
FUNCTION="$(python3 -c "import json; print(json.load(open('$ROOT/.iacguard.json'))['function'])")"

START="$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)"
END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

show() { # namespace metric stat [dimensions...]
  local ns="$1" metric="$2" stat="$3"; shift 3
  local value
  value=$(aws cloudwatch get-metric-statistics \
    --namespace "$ns" --metric-name "$metric" \
    --start-time "$START" --end-time "$END" \
    --period 3600 --statistics "$stat" \
    --region "$REGION" "$@" \
    --query "Datapoints[0].$stat" --output text 2>/dev/null)
  printf "  %-22s %s\n" "$metric" "${value:-none}"
}

echo "IaCGuard metrics (last hour, $REGION)"
for m in ScansCompleted FindingsTotal CriticalFindings HighFindings \
         NovaInputTokens NovaOutputTokens; do
  show IaCGuard "$m" Sum
done
show IaCGuard PostureScore Average
echo
echo "Scanner Lambda"
for m in Invocations Errors Throttles; do
  show AWS/Lambda "$m" Sum --dimensions "Name=FunctionName,Value=$FUNCTION"
done
show AWS/Lambda Duration Average --dimensions "Name=FunctionName,Value=$FUNCTION"
