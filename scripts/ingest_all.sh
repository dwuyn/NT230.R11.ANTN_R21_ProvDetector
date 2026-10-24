#!/usr/bin/env bash
# Parse the published Windows ETW traces into data/clean/*.parquet.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=.venv/bin/python
WS12=data/raw/pku/SimulatedWS12/SimulatedWS12/extracted
W10=data/raw/pku/SimulatedW10/realAPTWin10/extracted/win10
$PY -m src.ingest.parse_pku "$WS12/benign.json"  data/clean WS12 benign
$PY -m src.ingest.parse_pku "$WS12/anomaly.json" data/clean WS12 anomaly
$PY -m src.ingest.parse_pku "$W10/benign.json"   data/clean W10  benign
$PY -m src.ingest.parse_pku "$W10/anomaly.json"  data/clean W10  anomaly
