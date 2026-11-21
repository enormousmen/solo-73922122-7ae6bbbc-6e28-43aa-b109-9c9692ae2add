#!/usr/bin/env bash
# Guarded pool switch demo (allow + three refusals) against a running API.
#
#   docker compose up -d --build
#   ./scripts/demo-guarded.sh
#   BASE=http://host:8000 OPERATOR_TOKEN=... ./scripts/demo-guarded.sh
set -euo pipefail
exec python3 "$(dirname "$0")/demo_guarded.py" "$@"
