#!/usr/bin/env bash
# Runs the interop harness end-to-end. Use this from CI or locally.
#
# Prereqs:
#   - Go (matches go.mod)
#   - Python 3 with: pip install rns lxmf
#   - rnsd on PATH (provided by `pip install rns`)
#
# Usage:
#   bash tests/interop/run.sh            # run all cases
#   bash tests/interop/run.sh -run NAME  # filter via -run, e.g. opportunistic_short
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "==> interop harness"
exec go test -tags=interop -v -count=1 -timeout 5m ./tests/interop/... -run TestHarness "$@"
