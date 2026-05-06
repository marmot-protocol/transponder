#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "::error::Usage: read-coverage-metric.sh <metric-name> <coverage-json> <jq-filter>" >&2
  exit 64 # EX_USAGE
fi

metric_name="$1"
coverage_json="$2"
jq_filter="$3"

if [ ! -f "$coverage_json" ]; then
  echo "::error::Coverage file not found: ${coverage_json}" >&2
  exit 66 # EX_NOINPUT
fi

if ! value=$(jq -er "${jq_filter} | if type == \"number\" then . else error(\"coverage metric is not numeric\") end" "$coverage_json"); then
  echo "::error::Coverage metric is missing or not numeric: ${metric_name}" >&2
  exit 65 # EX_DATAERR
fi

if [[ ! "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "::error::Coverage metric is not a finite decimal: ${metric_name}" >&2
  exit 65 # EX_DATAERR
fi

printf '%s\n' "$value"
