#!/usr/bin/env bash
# Parse the Ubuntu Sysdig trace with published attack annotations.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=.venv/bin/python
RAW=data/raw/pku/SimulatedUbuntu
INNER=$RAW/realAPTlinux/hw17.zip
EXTRACTED=$RAW/realAPTlinux/extracted/hw17
if [ ! -f "$EXTRACTED/benign.json" ]; then
  mkdir -p "$RAW/realAPTlinux/extracted"
  unzip -oq "$INNER" -d "$RAW/realAPTlinux/extracted"
fi
$PY -m src.ingest.parse_sysdig "$EXTRACTED/anomaly.json" data/clean Ubuntu anomaly \
  --annotations "$RAW/annotations"
$PY -m src.ingest.parse_sysdig "$EXTRACTED/benign.json" data/clean Ubuntu benign
