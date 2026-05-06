#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build
GOOS=linux GOARCH=arm64           go build -o build/fwdsvc-linux-arm64 ./cmd/fwdsvc
GOOS=linux GOARCH=arm GOARM=7     go build -o build/fwdsvc-linux-armv7 ./cmd/fwdsvc
GOOS=linux GOARCH=amd64           go build -o build/fwdsvc-linux-amd64 ./cmd/fwdsvc
ls -lh build
