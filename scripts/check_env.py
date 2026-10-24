#!/usr/bin/env python3
"""Verify the pinned environment for the R21 reproduction."""
import json
import sys

import gensim
import matplotlib
import networkx
import numpy
import pandas
import pyarrow
import sklearn

EXPECTED = {
    "python": (3, 12),
    "numpy": "1.26.4",
    "pandas": "2.2.3",
    "scikit-learn": "1.5.2",
    "gensim": "4.4.0",
    "networkx": "3.4.2",
}

def main() -> int:
    versions = {
        "python": ".".join(map(str, sys.version_info[:3])),
        "numpy": numpy.__version__,
        "pandas": pandas.__version__,
        "scikit-learn": sklearn.__version__,
        "gensim": gensim.__version__,
        "networkx": networkx.__version__,
        "matplotlib": matplotlib.__version__,
        "pyarrow": pyarrow.__version__,
    }
    problems = []
    if sys.version_info[:2] != EXPECTED["python"]:
        problems.append(f"python: expected {EXPECTED['python']}, got {sys.version_info[:2]}")
    for pkg in ("numpy", "pandas", "scikit-learn", "gensim", "networkx"):
        if versions[pkg] != EXPECTED[pkg]:
            problems.append(f"{pkg}: expected {EXPECTED[pkg]}, got {versions[pkg]}")
    print(json.dumps(versions, indent=2))
    if problems:
        print("\nENV MISMATCH:")
        print("\n".join(problems))
        return 1
    print("\nENV OK")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
