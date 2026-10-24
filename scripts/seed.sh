#!/usr/bin/env bash
# Deterministic seeds for every stage. Usage: source scripts/seed.sh
set -euo pipefail
export PYTHONHASHSEED="${PYTHONHASHSEED:-20261025}"
export R21_SEED="${R21_SEED:-20261025}"
python - <<'PY'
import os, random
import numpy as np
try:
    import torch
except ImportError:
    torch = None
seed = int(os.environ["R21_SEED"])
random.seed(seed)
np.random.seed(seed)
if torch is not None:
    torch.manual_seed(seed)
print(f"seed={seed} PYTHONHASHSEED={os.environ['PYTHONHASHSEED']}")
PY
